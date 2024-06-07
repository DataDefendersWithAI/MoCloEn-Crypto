from flask import Blueprint, request, jsonify, session, redirect, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from MoClon.db import get_user
from flask_cors import CORS
from datetime import datetime
import uuid
import hashlib

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
                return {
                    "status": "success",
                    "message": "User login successful",
                }
            elif find_user is None:
                return {
                    "status": "fail",
                    "message": "User not found"
                }, 404
            else: return {
                "status": "fail",
            }, 401
            
        except Exception:
            return {
                "status": "fail",
            }, 401
    else:
        return {
                'status': "fail",
                'message':"Please register or login to access this page"
                }, 401