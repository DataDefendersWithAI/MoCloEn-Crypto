from flask import Blueprint, request, jsonify, session, current_app, redirect, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from MoClon.db import add_transaction, get_transaction, get_user
from MoClon.api.crypto_helper import CryptoHelper

from flask_cors import CORS
from datetime import datetime
import json
import uuid

import casbin
from casbin import Enforcer

transactions_api_v1 = Blueprint( 'transactions_api_v1', 'transactions_api_v1', url_prefix='/api/v1/transactions')

CORS(transactions_api_v1)

################################################################
#ACCESS CONTROLS

def balance_check(balance, amount):
    return balance >= amount

def d_transfer_access():
    e = Enforcer("MoClon/accessControl/models/transaction.conf", "MoClon/accessControl/policies/transaction.csv")
    e.add_function("balance_check", balance_check)
    return e

def d_transfer_get_access():
    e = Enforcer("MoClon/accessControl/models/transaction_get.conf", "MoClon/accessControl/policies/transaction_get.csv")
    return e

def d_transfer_user_access():
    e = Enforcer("MoClon/accessControl/models/transaction_user.conf", "MoClon/accessControl/policies/transaction_user.csv")
    return e

transfer_get_access = d_transfer_get_access()
transfer_access = d_transfer_access()
transfer_user_access = d_transfer_user_access()
################################################################

@transactions_api_v1.route('/transaction/<user_id>/<transaction_id>', methods=['GET'])
@jwt_required()
def api_get_transaction(transaction_id):
    if transaction_id is None:
        return jsonify({'error': 'Transaction ID not provided'}), 400
    
    user = get_user(get_jwt_identity())
    #Check user access
    if not transfer_get_access.enforce(user):
        return jsonify({'error': 'Access denied'}), 400
    
    #get transaction
    transaction = get_transaction(transaction_id)
    return jsonify(transaction), 200

@transactions_api_v1.route('/transaction/all', methods=['GET'])
@jwt_required()
def api_get_all_transaction():
    user = get_user(get_jwt_identity())
    #Check user access
    if not transfer_get_access.enforce(user):
        return jsonify({'error': 'Access denied'}), 400
    #get all transaction
    transactions={}
    return jsonify(transactions), 200

@transactions_api_v1.route('/transaction-create', methods=['POST'])
@jwt_required()
def api_create_transaction():
    data = request.get_json()

    # My work: Create CryptoHelper object with params from session --------------------------
    # Check if user has all params in session
    if 'sign_algo' not in session or 'aes_mode' not in session \
        or 'salt' not in session or 'aes_keylength_bits' not in session \
        or 'hash_mode' not in session or 'ec_curve' not in session:
        return jsonify({'error': 'Missing parameters in session. Please redirect to /api/v1/keyexs/algo to create'}), 400

    crypto_helper = CryptoHelper(
        sign_algo=session['sign_algo'],
        aes_mode=session['aes_mode'],
        salt=session['salt'],
        aes_keylength_bits=session['aes_keylength_bits'],
        hash_mode=session['hash_mode'],
        ec_curve=session['ec_curve']
    )
    
    # Check if the user has aes_key
    aes_key = session.get('aes_key')
    if aes_key is None:
        # Redirect to /api/v1/keyexs/keyex to perform key exchange
        return jsonify({'error': 'No AES key in session. Please redirect to /api/v1/keyexs/keyex to create'}), 400
    # Decrypt and verify the data
    decrypted_data = crypto_helper.decrypt_and_verify(data, aes_key, 'encoded_AES_data', 'sign', 'public_key')
    if decrypted_data is None:
        return jsonify({'error': 'Invalid signature'}), 400
    
    ## End secure data retrieval ---------------------------

    transaction_data = json.loads(decrypted_data)

    #{
    # sender_uid:
    # recipient_uid:
    # amount:
    # message:
    # timestamp:
    #}
    user = get_user(get_jwt_identity())
    sender=  get_user(transaction_data['sender_uid'])
    receiver = get_user(transaction_data['recipient_uid'])
    if sender is None or receiver is None:
        return jsonify({'error': 'Sender or receiver not found'}), 400
    
    if not transfer_user_access.enforce(user, sender):
        return jsonify({'error': 'Access denied'}), 400

    amount = transaction_data['amount']
    message = transaction_data['message']

    # Check sender access
    if not transfer_access.enforce(sender, receiver, amount):
        #save as failed
        return jsonify({'status': 'failed', 'message': 'Access denied'}), 400
    
    if amount <= 0:
        #save as failed
        return jsonify({'status': 'failed', 'message': 'Invalid amount'}), 400

    # Check if the sender has enough balance using Casbin
    if sender.balance <= amount:
        #save as failed
        return jsonify({'status': 'failed', 'message': 'Insufficient balance'}), 400

    # Check if the sender and receiver are the same
    if sender.username == receiver.username:
        #save as failed
        return jsonify({'status': 'failed', 'message': 'Sender and receiver cannot be the same'}), 400

    # Update user balances (assuming successful transaction)
    sender.balance -= amount
    receiver.balance += amount

    # addition transaction data
    transaction_id = str(uuid.uuid4())
    
    transaction_data['status'] = 'success'
    transaction_data['message'] = message

    # Save the transaction to the database
    add_transaction({
        'transaction_id': transaction_id,
        'data': transaction_data
    })

    # Encrypt and sign (i don't know why this is done here, but i will do it anyway)
    encrypted_transaction = crypto_helper.encrypt_and_sign(json.dumps(transaction_data), aes_key, secret_key, public_key, 'data', 'sign', 'public_key')
    transactions[transaction_id] = {
        'status': "success",
        'transaction_id': transaction_id,
        'data': encrypted_transaction['encoded_AES_data'],
        'sign': encrypted_transaction['sign'],
        'public_key': encrypted_transaction['public_key']
    }

    # Custom response with your response
    response = {
        "status": "success",
        "message": "Transaction created successfully",
        "data": {
            "transaction_id": transaction_id
        }
    }

    # My work to encrypt and sign the transaction data --------------------------

    # Get secret key and public key from config, remember to client-friendly with ECDSA key
    secret_key = current_app.config['SECRET_KEY']
    public_key = current_app.config['PUBLIC_KEY']
    if session['sign_algo'] == 'ECDSA':
        secret_key = current_app.config['SECRET_KEY_EC']
        public_key = current_app.config['PUBLIC_KEY_EC']
    
    # Encrypt and sign the response
    encrypted_response = crypto_helper.encrypt_and_sign(json.dumps(response), aes_key, secret_key, public_key, 'data', 'sign', 'public_key')

    return jsonify(encrypted_response), 201

    # End secure data response ---------------------------
