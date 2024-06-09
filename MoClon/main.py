from flask import Flask, redirect, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

from MoClon.api.transactions import transactions_api_v1
from MoClon.api.authentication import authentications_api_v1
from MoClon.api.key_exchange import keyexs_api_v1

from json import JSONEncoder
from flask_cors import CORS

# from bson import json_util, ObjectId
from datetime import datetime, timedelta
from MoClon.config import DevelopmentConfig



def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')
    app.config.from_object(DevelopmentConfig)
    #cross origin
    CORS(app)
    JWTManager(app)

    #Blueprints
    app.register_blueprint(transactions_api_v1)
    app.register_blueprint(authentications_api_v1)
    app.register_blueprint(keyexs_api_v1)


    return app