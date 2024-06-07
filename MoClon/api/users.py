from flask import Blueprint, request, jsonify
from MoClon.db import add_user, get_user

from flask_cors import CORS
from datetime import datetime
import hashlib

users_api_v1 = Blueprint( 'users_api_v1', 'users_api_v1', url_prefix='/api/v1/users')

CORS(users_api_v1)


@users_api_v1.route('/user/<hashed_passwd>', methods=['GET'])
def api_get_user(hashed_passwd):
    response_object = get_user(hashed_passwd)
    return jsonify(response_object), 200

@users_api_v1.route('/user-create', methods=['POST'])
def api_create_user():
    data = request.get_json()
    if not data or 'name' not in data or 'username' not in data or 'password' not in data:
        return {
            "status": "fail",
            "message": "Invalid payload"
        }, 400
    #decrypt from client

    #create a new user
    hashed_password = hashlib.sha256(data['password'].encode() + data['username'].encode() ).hexdigest()

    user_data = {
        "name": data['name'],
        "username": data['username'],       
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

    add_user(data_saved)
    # return success message and user data

    return {
        "status": "success",
        "message": "User created successfully",
    }, 201