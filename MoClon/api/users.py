from flask import Blueprint, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from MoClon.db import add_user, get_user

from flask_cors import CORS
from datetime import datetime
import hashlib

users_api_v1 = Blueprint( 'users_api_v1', 'users_api_v1', url_prefix='/api/v1/users')

CORS(users_api_v1)



@users_api_v1.route('/user/<hashed_passwd>', methods=['GET'])
@jwt_required()
def api_get_user(hashed_passwd):
    response_object = get_user(hashed_passwd)
    return jsonify(response_object), 200
