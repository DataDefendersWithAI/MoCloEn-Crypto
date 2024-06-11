from flask import current_app, g, jsonify
from werkzeug.local import LocalProxy
from pymongo import MongoClient
from bson.objectid import ObjectId
from MoClon.api.crypto_helper import matchHashedText

# Redirect print to log file
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

def init_mongo():
    """
    Initialize MongoDB with credentials from the Flask config.
    """
    try:
        mongo_uri = current_app.config['MONGO_URI']
        client = MongoClient(mongo_uri)
        db = client.get_default_database()
        return db
    except Exception as e:
        print(f"Error initializing MongoDB: {str(e)}")
        return None

def get_db():
    """
    Configuration method to return MongoDB instance.
    """
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = init_mongo()
    return db

# Use LocalProxy to read the global db instance with just `db`
db = LocalProxy(get_db)

def add_user_secrets(new_user_data: dict) -> dict | None:
    """
    Inserts a user's encrypted keys into the `users` collection.
    """
    try:
        user_id = new_user_data.get("_id", None)
        if user_id is None:
            raise ValueError("User ID is required")
        
        user_secrets = {
            "keys": new_user_data.get("keys", []),
            "created_at": new_user_data.get("created_at"),
            "updated_at": new_user_data.get("updated_at")
        }

        # Ensure user_id is an ObjectId
        if not isinstance(user_id, ObjectId):
            user_id = ObjectId(user_id)

        # Insert the document
        result = db.users.update_one(
            {"_id": user_id},
            {"$set": user_secrets},
            upsert=True
        )

        if result.upserted_id:
            return {"_id": str(result.upserted_id)}
        else:
            return {"_id": str(user_id)}
    except Exception as e:
        print(f"Error adding user secrets: {str(e)}")
        return None

def get_user_secrets(user_id: str) -> dict | None:
    """
    Retrieves a user's encrypted keys from the `users` collection.
    """
    try:
        # Ensure user_id is an ObjectId
        if not isinstance(user_id, ObjectId):
            user_id = ObjectId(user_id)

        user_secrets = db.users.find_one({"_id": user_id})
        if user_secrets:
            return user_secrets
        else:
            return None
    except Exception as e:
        print(f"Error getting user secrets: {str(e)}")
        return None
    
def get_server_secret():
    """
    Retrieves the server's secret key from the `servers` collection.
    """
    try:
        server_secret = db.secrets.find_one({"type": "server"})
        if server_secret:
            return server_secret
        else:
            return None
    except Exception as e:
        print(f"Error getting server secret: {str(e)}")
        return None