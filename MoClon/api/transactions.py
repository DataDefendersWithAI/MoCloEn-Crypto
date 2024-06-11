from flask import Blueprint, request, jsonify, session, current_app, redirect, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from MoClon.db import add_transaction, get_transaction, get_user, get_user_by_username, get_user_by_hashes, update_balance, get_all_transactions
from MoClon.api.crypto_helper import CryptoHelper,decryptRequest, encryptResponse
from MoClon.api.payment_gw import mock_payment_gateway

from flask_cors import CORS
from datetime import datetime, timedelta
import json
import uuid

import casbin
from casbin import Enforcer

import sys
import logging
# Configure logging
logging.basicConfig(level=logging.INFO, filename='app.log', filemode='a', 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

logger = logging.getLogger()

# Custom print function
def custom_print(*args, **kwargs):
    message = ' '.join(map(str, args))
    logger.info(message)

# Override the built-in print function
print = custom_print

transactions_api_v1 = Blueprint( 'transactions_api_v1', 'transactions_api_v1', url_prefix='/api/v1/transactions')

CORS(transactions_api_v1)

################################################################
#ACCESS CONTROLS
def d_transfer_access():
    e = Enforcer("MoClon/accessControl/models/transaction.conf", "MoClon/accessControl/policies/transaction.csv")
    return e

def d_transfer_get_access():
    e = Enforcer("MoClon/accessControl/models/transaction_get.conf", "MoClon/accessControl/policies/transaction_get.csv")
    return e

def d_transfer_get_all_access():
    e = Enforcer("MoClon/accessControl/models/transaction_get_all.conf", "MoClon/accessControl/policies/transaction_get_all.csv")
    return e

transfer_get_all_access = d_transfer_get_all_access()
transfer_get_access = d_transfer_get_access()
transfer_access = d_transfer_access()
################################################################

def check_transaction_valid(from_, to_, req_, isTopup = False)->dict:
    if not isTopup:
        if (req_['amount'] <= 0):
            return {'status': 'fail', 'message': 'Invalid amount'}
        elif (req_['amount'] >= 1e4):
            return {'status': 'fail', 'message': 'The amount is too high please contact the support team to verify the amount'}
        elif (from_['data']['balance'] <= req_['amount']):
            return {'status': 'fail', 'message': 'Insufficient balance'}
        elif (from_['data']['username'] == to_['data']['username']):
            return {'status': 'fail', 'message': 'Invalid receiver'}
        elif (from_['data']['user_id'] == to_['data']['user_id']):
            return {'status': 'fail', 'message': 'Invalid receiver'}
        elif (from_['data']['attr']['auth'] >= 3):
            return {'status': 'fail', 'message': 'Insufficient privileges'}
        elif (to_['data']['attr']['auth'] >= 3):
            return {'status': 'fail', 'message': 'Insufficient privileges'}
        return {'status': 'success', 'message': 'Valid transaction'}
    else:
        if (req_['amount'] <= 0):
            return {'status': 'fail', 'message': 'Invalid amount'}
        elif (to_['data']['attr']['auth'] >= 3):
            return {'status': 'fail', 'message': 'Insufficient privileges'}
        return {'status': 'success', 'message': 'Valid transaction'}

@transactions_api_v1.route('/<transaction_id>', methods=['GET'])
@jwt_required()
def api_get_transaction(transaction_id):
    try:
        if transaction_id is None:
            return jsonify(encryptResponse({'error': 'Transaction ID not provided'})), 400
        user = get_user_by_hashes(get_jwt_identity())
        #get transaction
        transaction = get_transaction(transaction_id)
        #Check user access
        if not transfer_get_access.enforce(user,transaction):
            return jsonify(encryptResponse({'error': 'Access denied'})), 400
        
        return jsonify(encryptResponse(transaction)), 200
    except Exception as e:
        print(e)
        return jsonify(encryptResponse({'error': 'An error occurred while getting transaction'})), 500

@transactions_api_v1.route('/all', methods=['GET'])
@jwt_required()
def api_get_all_transaction():
    try:
        user = get_user_by_hashes(get_jwt_identity())    
        #Check user access
        if not transfer_get_all_access.enforce(user):
            return jsonify(encryptResponse({'error': 'Access denied'})), 400
        #get all transaction
        transactions= get_all_transactions()
        return jsonify(encryptResponse({ 
            "status": "success",
            "data": transactions
            })), 200
    except Exception as e:
        print(e)
        return jsonify(encryptResponse({'error': 'An error occurred while getting transactions'})), 500


@transactions_api_v1.route('/create', methods=['POST'])
@jwt_required()
def api_create_transaction():
    try:
        data = request.get_json()
        transaction_data = decryptRequest(data)
        
        if 'error' in transaction_data:
            return jsonify(encryptResponse({
                "status": "fail",
                "message": "An error occurred while creating transaction: " + transaction_data['error']
            })), 400

        if not transaction_data or 'receiver_username' not in transaction_data \
            or 'amount' not in transaction_data or 'timestamp' not in transaction_data or 'type' not in transaction_data:
            return jsonify(encryptResponse({
                "status": "fail",
                "message": "Invalid payload"
            })), 400

        # timestamp check
        timestamp = datetime.fromisoformat(transaction_data['timestamp'])
        # Check if the timestamp is in the future or older than 3 minutes
        if timestamp > datetime.now() or timestamp < datetime.now() - timedelta(minutes=3):
            return jsonify(encryptResponse({
                "status": "fail",
                "message": "Invalid timestamp"
            })), 400

        sender_acc = get_user_by_hashes(get_jwt_identity())
        receiver_acc = get_user_by_username(transaction_data['receiver_username'])    

        check = check_transaction_valid(sender_acc, receiver_acc, transaction_data)
        if check is None or check['status'] =='fail':
            #save as failed
            return jsonify(encryptResponse(check)), 400

        transaction_id = str(uuid.uuid4())
        amount = transaction_data['amount']
        # Update user balances (assuming successful transaction)
        sender_acc['data']['balance'] -= amount
        receiver_acc['data']['balance'] += amount
        sender_acc['data']['transactions'].append(transaction_id)
        receiver_acc['data']['transactions'].append(transaction_id)
        
        update_balance([sender_acc, receiver_acc])

        # addition transaction data
        transaction_data['sender_username'] = sender_acc['data']['username']
        # Save the transaction to the database
        add_transaction({
            'transaction_id': transaction_id,
            'data': transaction_data,
            'status': "success",
            'status_msg': "Transaction created successfully",
        })

        
        return jsonify(encryptResponse({
            "status": "success",
            "message": "Transaction created successfully",
            "data":  transaction_id
        })), 200
    except Exception as e:
        print(e)
        return jsonify(encryptResponse({
            "status": "fail",
            "message": "An error occurred while creating transaction"
        })), 500
    # End secure data response ---------------------------

@transactions_api_v1.route('/topup', methods=['POST'])
@jwt_required()
def api_topup_transaction():
    try:
        data = request.get_json()
        transaction_data = decryptRequest(data)
        
        if 'error' in transaction_data:
            return jsonify(encryptResponse({
                "status": "fail",
                "message": "An error occurred while creating transaction: " + transaction_data['error']
            })), 400

        if not transaction_data or 'receiver_username' not in transaction_data \
            or 'amount' not in transaction_data or 'timestamp' not in transaction_data or 'type' not in transaction_data:
            return jsonify(encryptResponse({
                "status": "fail",
                "message": "Invalid payload"
            })), 400

        # timestamp check
        timestamp = datetime.fromisoformat(transaction_data['timestamp'])
        # Check if the timestamp is in the future or older than 3 minutes
        if timestamp > datetime.now() or timestamp < datetime.now() - timedelta(minutes=3):
            return jsonify(encryptResponse({
                "status": "fail",
                "message": "Invalid timestamp"
            })), 400


        # Mock payment gateway integration
        payment_gateway_response = mock_payment_gateway(transaction_data['amount'])
        if payment_gateway_response.get('status') != 'success':
            return jsonify(encryptResponse({
                "status": "fail",
                "message": "Payment gateway error: " + payment_gateway_response.get('message', 'Unknown error')
            })), 400

        receiver_acc = get_user_by_hashes(get_jwt_identity())

        check = check_transaction_valid(None, receiver_acc, transaction_data, True)
        if check is None or check['status'] =='fail':
            #save as failed
            return jsonify(encryptResponse(check)), 400

        transaction_id = str(uuid.uuid4())
        amount = transaction_data['amount']
        # Update user balances (assuming successful transaction)
        receiver_acc['data']['balance'] += amount
        receiver_acc['data']['transactions'].append(transaction_id)
        
        update_balance([receiver_acc])

        # addition transaction data
        transaction_data['sender_username'] = "Debit card"
        transaction_data['currency'] = "USD"
        # Save the transaction to the database
        add_transaction({
            'transaction_id': transaction_id,
            'data': transaction_data,
            'status': "success",
            'status_msg': "Top up "+ amount +"$ successfully",
        })

        
        return jsonify(encryptResponse({
            "status": "success",
            "message": "Top up "+ amount +"$ successfully",
            "data":  transaction_id
        })), 200
    except Exception as e:
        print(e)
        return jsonify(encryptResponse({
            "status": "fail",
            "message": "An error occurred while creating transaction"
        })), 500
    # End secure data response ---------------------------