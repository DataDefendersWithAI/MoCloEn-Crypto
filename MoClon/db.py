import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1.base_query import FieldFilter
from flask import current_app, g,jsonify
from werkzeug.local import LocalProxy
from MoClon.api.crypto_helper import matchHashedText

def init_firestore():
    """
    Initialize Firestore with Firebase credentials.
    """
    try:
        if not firebase_admin._apps:
            cred = credentials.Certificate(current_app.config['FIREBASE_KEY_PATH'])
            firebase_admin.initialize_app(cred)
            #print("Initializing Firestore with Firebase credentials")
        else:
            #print("Reusing Firestore with Firebase credentials")
            pass
        return firestore.client()
    except Exception as e:
        #print(f"Error initializing Firestore: {str(e)}")
        return None
    
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

def add_user(new_user_data: dict) -> dict| None:
    """
    Inserts a user into the `users` collection.
    """
    try:
        coll = db.collection('users')
        query = coll.where(filter=FieldFilter('data.username', '==', new_user_data['data']['username'])).stream()

        for doc in query:
            return{
                "status": "fail",
                "message": "User already exists"
            }

        upd_time, user_ref = coll.document(new_user_data['data']['user_id']).set(new_user_data)
        return {
            "status": "success",
            "message": "Account created successfully at " + str(upd_time.isoformat()),
            "data": user_ref.data.user_id,
        }
    except Exception as e:
        print(e)
        return

def add_transaction(transaction_data: dict) -> dict |None:
    """
    Inserts a transaction into the `transactions` collection.
    """
    try:
        db.collection('transactions').document(transaction_data['transaction_id']).set(transaction_data)
        return {
            "status": "success",
            "message": "Transaction added successfully"
        }
    except Exception as e:
        print(e)
        return

def get_user(username: str, password: str) -> dict|None:
    """
    Given a username and password, returns a user from the `users` collection.
    """
    try:
        coll = db.collection('users')
        query = coll.where(filter=FieldFilter('data.username', '==', username)).stream()
        for doc in query:
            user = doc.to_dict()
            if matchHashedText(user['hashes'],  password + username , user['salt']):
                return user
        return {
            "status": "fail",
            "message": "User not found"
        }
    except Exception as e:
        print(e)
        return

def get_user_by_username(username: str) -> dict|None:
    """
    Given a username returns a user from the `users` collection.
    """
    try:
        coll = db.collection('users')
        query = coll.where(filter=FieldFilter('data.username', '==', username)).stream()
        for doc in query:
            user = doc.to_dict()
            return user
        return {
            "status": "fail",
            "message": "User not found"
        }
    except Exception as e:
        print(e)

def get_user_by_hashes(hashes:str) ->dict | None:
    """
    Given a hashed password, returns a user from the `users` collection.
    """
    try:
        coll = db.collection('users')
        query = coll.where(filter=FieldFilter('hashes', '==', hashes)).stream()
        for doc in query:
            user = doc.to_dict()
            return user
        return {
            "status": "fail",
            "message": "User not found"
        }
    except Exception as e:
        print(e)
        return

def get_transaction(transaction_id: str) -> dict | None:
    """
    Given a transaction_id, returns a transaction from the `transactions` collection.
    """
    try:
        doc = db.collection('transactions').document(transaction_id).get()
        if doc.exists:
            return doc.to_dict()
        return {
            "status": "fail",
            "message": "Transaction not found"
        }
    except Exception as e:
        print(e)
        return

def update_balance(users: list) -> dict | None:
    """
    Updates the balance of a user in the `users` collection.

    Args:
        users (List[Dict]): A list of user dictionaries containing 'hashes' and 'data.balance'.

    Returns:
        dict: A dictionary containing the status and message of the operation.
    """
    try:
        coll = db.collection('users')
        for user in users:
            # Query the collection
            query = coll.where(filter=FieldFilter('hashes', '==', user['hashes'])).stream()
            for doc in query:
                doc_ref = coll.document(doc.id)  # Get the DocumentReference
                doc_ref.update({"data.balance": user['data']['balance'], "data.transactions": user['data']['transactions']})

                break                

        return {
            "status": "success",
            "message": "Balance updated successfully"
        }
    except Exception as e:
        print(e)
        return 

def get_all_transactions():
    """
    Returns all transactions from the `transactions` collection.
    """
    try:
        coll = db.collection('transactions')
        query = coll.stream()
        transactions = []
        for doc in query:
            transactions.append(doc.to_dict())
        return transactions
    except Exception as e:
        print(e)
        return
    
    