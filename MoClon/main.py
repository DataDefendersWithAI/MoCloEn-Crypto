from flask import Flask, redirect, url_for
from MoClon.api.users import users_api_v1
from MoClon.api.accounts import accounts_api_v1
from MoClon.api.transactions import transactions_api_v1

from json import JSONEncoder
from flask_cors import CORS

from bson import json_util, ObjectId
from datetime import datetime, timedelta



def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')
    #Database config
    #Bcrypt config
    #Login config
    #cross origin
    CORS(app)

    #Blueprints
    app.register_blueprint(users_api_v1)
    app.register_blueprint(accounts_api_v1)
    app.register_blueprint(transactions_api_v1)

    return app