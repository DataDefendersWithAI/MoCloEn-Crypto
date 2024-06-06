from flask import Blueprint, request, jsonify, session, current_app

from flask_cors import CORS
from datetime import datetime

from MoClon.api.crypto_helper import decrypt_and_verify, encrypt_and_sign, AES_KEYLENGTH, SALT, HASH_MODE, EC_CURVE
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from Crypto.Protocol.KDF import HKDF

import ast


keyexs_api_v1 = Blueprint( 'keyexs_api_v1', 'keyexs_api_v1', url_prefix='/api/v1/keyexs')

CORS(keyexs_api_v1)


# @keyexs_api_v1.route('/keyex/<keyex_id>', methods=['GET'])
# def api_get_keyex(keyex_id):
#     response_object ={
#         "keyex": "John Doe",
#         "id": keyex_id,
#     }
#     return jsonify(response_object), 200

# @keyexs_api_v1.route('/keyex-create', methods=['POST'])
# def api_create_keyex():
#     data = request.get_json()
#     #expect(data, 'keyexname', 'password')
#     response_object = {
#         "keyex": data['keyexname'],
#         "id": 1,
#     }
#     return jsonify(response_object), 201

server_private_key = ec.generate_private_key(EC_CURVE())
server_public_key = server_private_key.public_key()

# Receive client public key, perform ECDH key exchange, derive AES key, and send server public key
@keyexs_api_v1.route('/keyex', methods=['POST'])
def api_ecdh():
    """
    Receive client public key, perform ECDH key exchange, derive AES key, and send server public key
    """
    # Load server private key
    secret_key = current_app.config['SECRET_KEY']
    secret_key = ast.literal_eval(secret_key)
    public_key = current_app.config['PUBLIC_KEY']
    public_key = ast.literal_eval(public_key)
    # Receive request
    client_request = request.get_json()
    client_public_key = decrypt_and_verify(client_request, None, 'client_public_key')
    if client_public_key is None:
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
    server_response = encrypt_and_sign(server_public_pem, None, secret_key, public_key, 'server_public_key')
    return jsonify(server_response)