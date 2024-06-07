from flask import Blueprint, request, jsonify, current_app, session
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from MoClon.db import add_account, get_account,get_user
from MoClon.api.crypto_helper import CryptoHelper
from flask_cors import CORS
from datetime import datetime
import uuid
import json
import casbin
from casbin import Enforcer

accounts_api_v1 = Blueprint('accounts_api_v1', 'accounts_api_v1', url_prefix='/api/v1/accounts')

CORS(accounts_api_v1)

################################################################
#ACCESS CONTROLS

def d_account_get_access():
    e = Enforcer("MoClon/accessControl/models/account_get.conf", "MoClon/accessControl/policies/account_get.csv")
    return e

account_get_access = d_account_get_access()
################################################################


@accounts_api_v1.route('/account/<account_id>', methods=['GET'])
@jwt_required()
def api_get_account(account_id):
    user = get_user(get_jwt_identity())
    #Check user access
    if not account_get_access.enforce(user):
        return jsonify({'error': 'Access denied'}), 400
    
    account = get_account(account_id)
    if account:
        response_object = {
            "status": "success",
            "data": {
                "account": account
            }
        }
        return jsonify(response_object), 200
    else:
        response_object = {
            "status": "fail",
            "message": "Account not found"
        }
        return jsonify(response_object), 404

@accounts_api_v1.route('/account-create', methods=['POST'])
@jwt_required()
def api_create_account():
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
    account_data = json.loads(decrypted_data)

    if 'account_name' not in account_data or 'account_type' not in account_data:
        response_object = {
            "status": "fail",
            "message": "Invalid payload"
        }
        return jsonify(response_object), 400

    user = get_user(get_jwt_identity())
    #Check user access
    if not account_get_access.enforce(user):
        return jsonify({'error': 'Access denied'}), 400

    new_account_id = str(uuid.uuid4())
    account = {
        "account_name": data['account_name'],
        "balance": 0,
        "account_type": data['account_type'],
        "created_at": datetime.now()
    }

    account_enc = account

    saved_account = {
        "data": account_enc,
        "id": new_account_id,
    }

    add_account(saved_account)

    response = {
        "status": "success",
        "message": "Account created successfully",
        "data": {
            "account": saved_account
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
