from flask import Blueprint, request, jsonify
from MoClon.db import add_user, get_user

from flask_cors import CORS
from datetime import datetime


users_api_v1 = Blueprint( 'users_api_v1', 'users_api_v1', url_prefix='/api/v1/users')

CORS(users_api_v1)


@users_api_v1.route('/user/<user_id>', methods=['GET'])
def api_get_user(user_id):
    response_object ={
        "user": "John Doe",
        "id": user_id,
    }
    return jsonify(response_object), 200

@users_api_v1.route('/user', methods=['POST'])
def api_create_user():
    data = request.get_json()
    #expect(data, 'username', 'password')
    response_object = {
        "user": data['username'],
        "id": 1,
    }
    return jsonify(response_object), 201