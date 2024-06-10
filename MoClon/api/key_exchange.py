from flask import Blueprint, request, jsonify, session, current_app
from flask_cors import CORS
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import ast
from MoClon.api.crypto_helper import CryptoHelper
import base64

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

keyexs_api_v1 = Blueprint('keyexs_api_v1', 'keyexs_api_v1', url_prefix='/api/v1/keyexs')
CORS(keyexs_api_v1)

# Set all algorithms and parameters into user session
@keyexs_api_v1.route('/algo', methods=['POST'])
def api_algo():
    """
    Set all algorithms and parameters into user session
    """
    # Receive request
    client_request = request.get_json()
    print(client_request)
    # Test client request parameters
    try:
        CryptoHelper(
            sign_algo=client_request["sign_algo"],
            aes_mode=client_request["aes_mode"],
            salt=client_request["salt"],
            aes_keylength_bits=client_request["aes_keylength_bits"],
            hash_mode=client_request["hash_mode"],
            ec_curve=client_request["ec_curve"]
        )
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    # Load parameters
    session["sign_algo"] = client_request["sign_algo"]
    session["aes_mode"] = client_request["aes_mode"]
    session["salt"] = client_request["salt"]
    session["aes_keylength_bits"] = client_request["aes_keylength_bits"]
    session["hash_mode"] = client_request["hash_mode"]
    session["ec_curve"] = client_request["ec_curve"]
    session["aes_keylength"] = session["aes_keylength_bits"] // 8
    # Return response
    return jsonify({'success': 'Algorithms and parameters set'})

# Receive client public key, perform ECDH key exchange, derive AES key, and send server public key
@keyexs_api_v1.route('/keyex', methods=['POST'])
def api_ecdh():
    """
    Receive client public key, perform ECDH key exchange, derive AES key, and send server public key
    """
    try:
        crypto = CryptoHelper(
            sign_algo=session["sign_algo"],
            aes_mode=session["aes_mode"],
            salt=session["salt"],
            aes_keylength_bits=session["aes_keylength_bits"],
            hash_mode=session["hash_mode"],
            ec_curve=session["ec_curve"]
        )
        
        # Generate server's key pair based on the specified curve
        if session["ec_curve"].lower() == "curve25519":
            server_private_key = x25519.X25519PrivateKey.generate()
            server_public_key = server_private_key.public_key()
        else:
            curve = crypto.get_ec_curve(session["ec_curve"])
            server_private_key = ec.generate_private_key(curve)
            server_public_key = server_private_key.public_key()
        
        # Load server private key
        secret_key = current_app.config['SECRET_KEY']
        print(type(secret_key))
        # secret_key = ast.literal_eval(secret_key)
        public_key = current_app.config['PUBLIC_KEY']
        print(type(public_key))
        # public_key = ast.literal_eval(public_key)

        if session["ec_curve"].lower() == "curve25519" and session["sign_algo"] == "ECDSA":
            # Load server private key but ECDSA
            secret_key = current_app.config['SECRET_KEY_EC']
            print(type(secret_key))
            # secret_key_ec = ast.literal_eval(secret_key_ec)
            public_key = current_app.config['PUBLIC_KEY_EC']
            print(type(public_key))
            # public_key_ec = ast.literal_eval(public_key_ec)
        
        # Receive request
        client_request = request.get_json()
        # print(f"Client request: {client_request}")
        client_public_key_pem = client_request.get('client_public_key')
        signature = base64.b64decode(client_request.get('signature'))
        signature_public_key = base64.b64decode(client_request.get('signature_public_key'))
        
        # print(f"Client Public Key PEM: {client_public_key_pem}")
        # print(f"Signature: {signature}")
        # print(f"Signature Public Key: {signature_public_key}")

        try:
            client_public_key_pem = client_request['client_public_key']
            if not crypto.verify_signature(client_public_key_pem.encode('utf-8'), signature, signature_public_key):
                return jsonify({'error': 'Invalid signature'}), 400
            client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode('utf-8'))
        except Exception as e:
            print(f"Error loading client public key: {e}")
            return jsonify({'error': 'Unable to load client public key'}), 400
        
        # Load client's public key
        client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode())

        # Perform ECDH key exchange
        if isinstance(server_private_key, x25519.X25519PrivateKey):
            shared_key = server_private_key.exchange(client_public_key)
        else:
            shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
        
        # Derive AES key
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=crypto.aes_keylength,
            salt=crypto.salt,
            info=None
        ).derive(shared_key)
        
        session['aes_key'] = aes_key
        
        # Convert server public key to PEM format
        server_public_pem = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Wrap server response
        server_response = crypto.encrypt_and_sign(server_public_pem, None, secret_key, public_key, 'server_public_key')
        return jsonify(server_response)
    except Exception as e:
        print(f"Error in key exchange: {e}")
        return jsonify({'error': 'Unable to perform key exchange'}), 400