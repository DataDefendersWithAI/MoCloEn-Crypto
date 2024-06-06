from flask import Flask, redirect, url_for
from .db import db
from MoClon.api.users import users_api_v1
from MoClon.api.accounts import accounts_api_v1
from MoClon.api.transactions import transactions_api_v1

from json import JSONEncoder
from flask_cors import CORS
from flask_pymongo import PyMongo

from bson import json_util, ObjectId
from datetime import datetime, timedelta
#from mflix.api.movies import movies_api_v1

class MongoJsonEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(obj, ObjectId):
            return str(obj)
        return json_util.default(obj, json_util.CANONICAL_JSON_OPTIONS)


def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')
    #Database config
    #Bcrypt config
    #Login config
    #cross origin
    CORS(app)
    #json encoder
    app.json_encoder = MongoJsonEncoder
    #Blueprints
    app.register_blueprint(users_api_v1)
    app.register_blueprint(accounts_api_v1)
    app.register_blueprint(transactions_api_v1)

    return app