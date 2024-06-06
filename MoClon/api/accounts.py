from flask import Blueprint, request, jsonify
from MoClon.db import add_account, get_account
from flask_cors import CORS
from datetime import datetime
import uuid

accounts_api_v1 = Blueprint('accounts_api_v1', 'accounts_api_v1', url_prefix='/api/v1/accounts')

CORS(accounts_api_v1)

@accounts_api_v1.route('/account/<account_id>', methods=['GET'])
def api_get_account(account_id):
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
def api_create_account():
    data = request.get_json()
    if not data or 'accountname' not in data or 'password' not in data:
        response_object = {
            "status": "fail",
            "message": "Invalid payload"
        }
        return jsonify(response_object), 400

    new_account_id = str(uuid.uuid4())
    new_account = {
        "id": new_account_id,
        "accountname": data['accountname'],
        "password": data['password'], # In a real application, ensure to hash the password
        "created_at": datetime.now()
    }

    add_account(new_account)

    response_object = {
        "status": "success",
        "message": "Account created successfully",
        "data": {
            "account": new_account
        }
    }
    return jsonify(response_object), 201
