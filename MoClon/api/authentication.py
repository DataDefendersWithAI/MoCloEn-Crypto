from flask import Blueprint, request, jsonify, session, redirect, url_for,current_app
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from MoClon.db import get_user, add_user
from MoClon.api.crypto_helper import CryptoHelper
from flask_cors import CORS
from datetime import datetime
import uuid
import hashlib
import json

authentications_api_v1 = Blueprint('authentications_api_v1', 'authentications_api_v1', url_prefix='/api/v1/authentications')

CORS(authentications_api_v1)

@authentications_api_v1.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        user_name = request.form['username']
        user_password = request.form['password']
        hashed_password = hashlib.sha256(user_password.encode() + user_name.encode() ).hexdigest()
        
        try:
            find_user = get_user(hashed_password)
            if not find_user is None:
                session['type'] = 'normal'

                create_access_token(identity=find_user.data.user_id)

                redirect(url_for('users_api_v1.api_get_user'))
                return jsonify({
                    "status": "success",
                    "message": "User login successful",
                }), 200
            elif find_user is None:
                return jsonify({
                    "status": "fail",
                    "message": "User not found"
                }), 404
            else: return jsonify({
                "status": "fail",
            }), 401
            
        except Exception:
            return jsonify({
                "status": "fail",
            }), 401
    else:
        return jsonify({
                'status': "fail",
                'message':"Please register or login to access this page"
                }), 401


@authentications_api_v1.route('/register', methods=['POST'])
def register():
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

    register_data = json.loads(decrypted_data)
    
    if not register_data or 'name' not in register_data or 'username' not in register_data or 'password' not in register_data:
        return {
            "status": "fail",
            "message": "Invalid payload"
        }, 400
    #decrypt from client

    #create a new user
    hashed_password = hashlib.sha256(register_data['password'].encode() + register_data['username'].encode() ).hexdigest()

    user_data = {
        "user_id": str(uuid.uuid4()), #generate a unique id for the user
        "name": register_data['name'],
        "username": register_data['username'],       
        "role": 'user',
        "accounts":[],
        "date-created": datetime.now().isoformat(),
        "attr":{
            "veri": 0,
            "auth": 0
        }
    }

    #encryption to save to server
    enc_data = user_data #implement here

    data_saved = {
        "data": enc_data,
        "password": hashed_password,
    }

    response ={
        "status": "success",
        "message": "User created successfully",
        "data": user_data
    }

    add_user(data_saved)
    # return success message and user data

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