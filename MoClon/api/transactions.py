from flask import Blueprint, request, jsonify, session
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from MoClon.db import add_transaction, get_transaction, get_user

from flask_cors import CORS
from datetime import datetime

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
    # Check if the user has aes_key
    aes_key = session.get('aes_key')
    if aes_key is None:
        return jsonify({'error': 'No AES key in session'}), 400
    # Decrypt and verify the data
    decrypted_data = decrypt_and_verify(data, aes_key, 'encoded_AES_data', 'sign', 'public_key')
    if decrypted_data is None:
        return jsonify({'error': 'Invalid signature'}), 400
    
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
    
    #encypt transaction data
    encrypted_transaction = encrypt_and_sign(json.dumps(transaction_data), aes_key, secret_key, public_key, 'data', 'sign', 'public_key')
    transactions[transaction_id] = {
        'status': "success",
        'transaction_id': transaction_id,
        'data': encrypted_transaction['encoded_AES_data'],
        'sign': encrypted_transaction['sign'],
        'public_key': encrypted_transaction['public_key']
    }

    return {
        "status": "success",
        "message": "Transaction created successfully",
        "data": {
            "transaction_id": transaction_id
        }
    }, 201
