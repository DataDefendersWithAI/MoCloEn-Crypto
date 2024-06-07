from flask import Blueprint, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from MoClon.db import add_account, get_account,get_user
from flask_cors import CORS
from datetime import datetime
import uuid

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
    if not data or 'accountname' not in data or 'password' not in data:
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

    response_object = {
        "status": "success",
        "message": "Account created successfully",
        "data": {
            "account": saved_account
        }
    }
    return jsonify(response_object), 201
