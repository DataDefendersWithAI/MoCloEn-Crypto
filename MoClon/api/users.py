from flask import Blueprint, request, jsonify, session, current_app, redirect, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from MoClon.db import get_user
from MoClon.api.crypto_helper import CryptoHelper,decryptRequest, encryptResponse

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

users_api_v1 = Blueprint( 'users_api_v1', 'users_api_v1', url_prefix='/api/v1/users')

CORS(users_api_v1)

################################################################
################################################################

@users_api_v1.route('/get', methods=['GET'])
@jwt_required()
def getUser():
    #data = request.get_json()
    #user_data = decryptRequest(data)

    user_data = get_user(get_jwt_identity())
    if user_data is None:
        return jsonify(encryptResponse({
            "status": "fail",
            "message": "User not found"
        })), 404
    return jsonify(encryptResponse({
        "status": "success",
        "message": "User found",
        "data": user_data
    })), 200

