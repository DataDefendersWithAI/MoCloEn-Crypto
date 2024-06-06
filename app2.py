from flask import Flask, request, jsonify, session
import json
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64
import uuid
import oqs
from casbin import Enforcer

SIGN_ALGO = "Dilithium2"
AES_MODE = AES.MODE_GCM
SALT = None
AES_KEYLENGTH_BITS = 256
HASH_MODE = SHA256
EC_CURVE = ec.SECP256R1

# TODO1: Add /balance to check user money, with this implement check if topup amount is larger than 0, not equal 0
# TODO2: Enhance securuty on all requests and responses, all in encrypted and signed format, including error: Create helper functions:
# - encrypt_and_sign(data, key): 
# - decrypt_and_verify(data, key):
# TODO3: Implement ABAC on all payment processes, including: topup, make transaction,...
# TODO4: Add some ways to define all above constants in 1 session with /define-algo
# TODO5: Enhance ECDH with CRYSTALS-Kyber maybe 512 or 1024
# TODO6: Include Payment Gateway, with user-friendly client instead of client.py

AES_KEYLENGTH = AES_KEYLENGTH_BITS // 8

app = Flask(__name__)
app.secret_key = get_random_bytes(16)
transactions = {}
users = {}  # Store user balances
server_private_key = ec.generate_private_key(EC_CURVE())
server_public_key = server_private_key.public_key()

# Casbin setup
enforcer = Enforcer("model.conf", "policy.csv")

# Generate Dilithium keys for signing
def generate_keys():
    signer = oqs.Signature(SIGN_ALGO)
    public_key = signer.generate_keypair()
    return signer.export_secret_key(), public_key
secret_key, public_key = generate_keys()

def encrypt_aes_gcm(plaintext, key):
    cipher = AES.new(key, AES_MODE)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_aes_gcm(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES_MODE, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def sign_message(message, secret_key):
    signer = oqs.Signature(SIGN_ALGO, secret_key=secret_key)
    return signer.sign(message)

def verify_signature(message, signature, public_key):
    verifier = oqs.Signature(SIGN_ALGO)
    return verifier.verify(message, signature, public_key)

@app.route('/ecdh-key-exchange', methods=['POST'])
def ecdh_key_exchange():
    # Receive request
    client_request = request.get_json()
    client_public_key = client_request['client_public_key']
    signature = base64.b64decode(client_request['signature'])
    signature_public_key = base64.b64decode(client_request['signature_public_key'])
    # Check if message not change and from client request
    if not verify_signature(client_public_key.encode('utf-8'), signature, signature_public_key):
        return jsonify({'error': 'Invalid signature'}), 400
    # Load public key from ECDH
    client_public_key = serialization.load_pem_public_key(client_public_key.encode())
    shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
    # Derive key
    aes_key = HKDF(shared_key, AES_KEYLENGTH, salt=SALT, hashmod=HASH_MODE, num_keys=1)
    session['aes_key'] = aes_key
    server_public_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    # Wrap server response
    signature = sign_message(server_public_pem.encode("utf-8"), secret_key)
    server_response = {
        'server_public_key': server_public_pem,
        "signature": base64.b64encode(signature).decode('utf-8'),
        "signature_public_key": base64.b64encode(public_key).decode('utf-8')
    }
    return jsonify(server_response)

@app.route('/topup', methods=['POST'])
def topup():
    # Receive request
    data = request.get_json()
    encrypted_data = data['encoded_AES_data']
    signature = base64.b64decode(data['sign'])
    client_public_key = base64.b64decode(data['public_key'])
    aes_key = session.get('aes_key')
    if aes_key is None:
        return jsonify({'error': 'No AES key in session'}), 400
    if not verify_signature(encrypted_data.encode('utf-8'), signature, client_public_key):
        return jsonify({'error': 'Invalid signature'}), 400
    decrypted_data = decrypt_aes_gcm(encrypted_data, aes_key)
    topup_data = json.loads(decrypted_data)
    receiver = topup_data['receiver']
    amount = topup_data['amount']
    # Check if user amount is negative
    if amount < 0:
        return jsonify({'status': 'failed', 'message': 'Invalid amount'}), 400
    # Update user balance
    if receiver not in users:
        users[receiver] = {'balance': 0}
    users[receiver]['balance'] += amount
    
    # Wrap up message: users[receiver] + {"status": "success"}
    # Caution: Python >= 3.9 supports this operation
    message = users[receiver] | {"status": "success"}
    print(f"Top up: {json.dumps(message)}")
    # Encrypt and sign the updated user data
    encrypted_user_data = encrypt_aes_gcm(json.dumps(message).encode('utf-8'), aes_key)
    user_signature = sign_message(encrypted_user_data.encode('utf-8'), secret_key)
    response_data = {
        'data': encrypted_user_data,
        'signature': base64.b64encode(user_signature).decode('utf-8'),
        'signature_public_key': base64.b64encode(public_key).decode('utf-8')
    }
    return jsonify(response_data)


@app.route('/balance', methods=['POST'])

@app.route('/transaction', methods=['POST'])
def create_transaction():
    data = request.get_json()
    encrypted_data = data['encoded_AES_data']
    signature = base64.b64decode(data['sign'])
    client_public_key = base64.b64decode(data['public_key'])  # Decode Base64 back to binary
    
    aes_key = session.get('aes_key')
    if aes_key is None:
        return jsonify({'error': 'No AES key in session'}), 400
    
    if not verify_signature(encrypted_data.encode('utf-8'), signature, client_public_key):
        return jsonify({'error': 'Invalid signature'}), 400
    
    decrypted_data = decrypt_aes_gcm(encrypted_data, aes_key)
    transaction_data = json.loads(decrypted_data)

    # Check if the sender has enough balance
    sender = transaction_data['sender']
    receiver = transaction_data['receiver']
    amount = transaction_data['amount']

    # Check if the sender has enough balance using Casbin
    if not enforcer.enforce(sender, receiver, amount):
        return jsonify({'status': 'failed', 'message': 'Insufficient funds'}), 403
    
    print(f"Users: {users}")

    # Update user balances (assuming successful transaction)
    if sender not in users:
        users[sender] = {'balance': 0}
    if receiver not in users:
        users[receiver] = {'balance': 0}

    users[sender]['balance'] -= amount
    users[receiver]['balance'] += amount

    transaction_id = str(uuid.uuid4())
    transaction_data['id'] = transaction_id
    transaction_data['timestamp'] = datetime.now().isoformat()
    
    encrypted_transaction = encrypt_aes_gcm(json.dumps(transaction_data).encode('utf-8'), aes_key)
    signature = sign_message(encrypted_transaction.encode('utf-8'), secret_key)
    transactions[transaction_id] = {
        'data': encrypted_transaction,
        'signature': base64.b64encode(signature).decode('utf-8')
    }

    print(f"Users after transaction: {users}")
    
    return jsonify({'transaction_id': transaction_id, 'status': 'success'})

@app.route('/transaction/check', methods=['POST'])
def get_transaction():
    data = request.get_json()
    encrypted_data = data['encoded_AES_data']
    signature = base64.b64decode(data['sign'])
    client_public_key = base64.b64decode(data['public_key'])  # Decode Base64 back to binary
    
    aes_key = session.get('aes_key')
    if aes_key is None:
        return jsonify({'error': 'No AES key in session'}), 400
    
    if not verify_signature(encrypted_data.encode('utf-8'), signature, client_public_key):
        return jsonify({'error': 'Invalid signature'}), 400
    
    decrypted_data = decrypt_aes_gcm(encrypted_data, aes_key)
    transaction_id = decrypted_data.decode('utf-8')
    
    if transaction_id not in transactions:
        return jsonify({'error': 'Transaction not found'}), 404
    
    transaction = transactions[transaction_id]
    encrypted_transaction_data = transaction['data']
    transaction_signature = base64.b64decode(transaction['signature'])
    
    if not verify_signature(encrypted_transaction_data.encode('utf-8'), transaction_signature, public_key):
        return jsonify({'error': 'Invalid signature'}), 400
    
    return jsonify({
        'encoded_AES_data': encrypted_transaction_data,
        'sign': base64.b64encode(transaction_signature).decode('utf-8'),
        'public_key': base64.b64encode(public_key).decode('utf-8'),  # Encode public key in Base64
        'status': 'success'  # Or 'failed' if applicable
    })

if __name__ == '__main__':
    app.run(debug=True)
