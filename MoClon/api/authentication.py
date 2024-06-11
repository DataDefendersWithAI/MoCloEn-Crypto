from flask import Blueprint, request, jsonify, session, redirect, url_for,current_app
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from MoClon.db import get_user, add_user
from MoClon.vault import add_user_secrets
from MoClon.api.crypto_helper import CryptoHelper, hashText, encryptResponse, decryptRequest
from flask_cors import CORS
from datetime import datetime
import uuid
import hashlib
import json

authentications_api_v1 = Blueprint('authentications_api_v1', 'authentications_api_v1', url_prefix='/api/v1/authentications')

CORS(authentications_api_v1)

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

@authentications_api_v1.route('/login', methods=['GET', 'POST'])
def login():
    data = request.get_json()
    login_data = decryptRequest(data)

    user_name = login_data['username']
    user_password = login_data['password']
    find_user = get_user(user_name, user_password)

    if find_user is None or find_user.get('status') == 'fail':
        return jsonify(encryptResponse({
            "status": "fail",
            "message": "Invalid username or password"
        })), 500
    
    _user = find_user 
    session['type'] = 'normal'
    jwt = create_access_token(identity=_user['hashes'])
    return jsonify(encryptResponse({
        "status": "success",
        "message": "Login successful",
        "jwt": jwt
    })),200


@authentications_api_v1.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    register_data = decryptRequest(data)
    
    if not register_data or 'name' not in register_data or 'username' not in register_data or 'password' not in register_data:
        return jsonify(encryptResponse({
            "status": "fail",
            "message": "Invalid payload"
        })), 400
    #decrypt from client

    #check if username is a valid phone number
    if not register_data['username'].isdigit() or len(register_data['username']) != 10:
        return jsonify(encryptResponse({
            "status": "fail",
            "message": "Invalid username"
        })), 400

    #create a new user
    salt = str(uuid.uuid4())
    user_id = str(uuid.uuid4()) #generate a unique id for the user
    hashed_password = hashText(register_data['password'] + register_data['username'], salt)

    user_data = {
        "user_id": user_id, 
        "username": register_data['username'],    #phone number   
        "name": register_data['name'],      
        "account_type":"normal",
        "balance": 0.0,
        "date-created": datetime.now().isoformat(),
        "transactions":[],
        "attr":{
            "veri": 0,
            "auth": 0
        }
    }

    #encryption to save to server
    enc_data = user_data #implement here

    data_saved = {
        "salt": salt,
        "data": enc_data,
        "hashes": hashed_password,
    }

    respond = add_user(data_saved)
    if respond is None:
        return jsonify(encryptResponse({
            "status": "fail",
            "message": "An error occurred while creating the account"
        })), 500
    
    if respond.get('status') == 'fail':
        return jsonify(encryptResponse(respond)), 400

    return jsonify(encryptResponse(respond)), 201

