import firebase_admin
from firebase_admin import credentials, firestore
from flask import current_app, g
from werkzeug.local import LocalProxy

def init_firestore():
    """
    Initialize Firestore with Firebase credentials.
    """
    cred = credentials.Certificate(current_app.config['FIREBASE_KEY_PATH'])
    firebase_admin.initialize_app(cred)
    return firestore.client()

def get_db():
    """
    Configuration method to return Firestore instance
    """
    db = getattr(g, "_database", None)

    if db is None:
        db = g._database = init_firestore()
    
    return db

# Use LocalProxy to read the global db instance with just `db`
db = LocalProxy(get_db)

def add_user(userdata):
    """
    Inserts a user into the `users` collection.
    """
    return db.collection('users').add(userdata)

def add_account(accountdata):
    """
    Inserts an account into the `accounts` collection.
    """
    return db.collection('accounts').add(accountdata)

def add_transaction(transactiondata):
    """
    Inserts a transaction into the `transactions` collection.
    """
    return db.collection('transactions').add(transactiondata)

def get_user(user_id):
    """
    Given a user_id, returns a user from the `users` collection.
    """
    try:
        doc = db.collection('users').document(user_id).get()
        return doc.to_dict() if doc.exists else None
    except Exception as e:
        return str(e)

def get_account(account_id):
    """
    Given an account_id, returns an account from the `accounts` collection.
    """
    try:
        doc = db.collection('accounts').document(account_id).get()
        return doc.to_dict() if doc.exists else None
    except Exception as e:
        return str(e)

def get_transaction(transaction_id):
    """
    Given a transaction_id, returns a transaction from the `transactions` collection.
    """
    try:
        doc = db.collection('transactions').document(transaction_id).get()
        return doc.to_dict() if doc.exists else None
    except Exception as e:
        return str(e)
