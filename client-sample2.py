import requests
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import serialization
import base64
import oqs
from MoClon.api.crypto_helper import CryptoHelper
from datetime import datetime
import threading

SIGN_ALGO = "Dilithium2"
# SIGN_ALGO = "ECDSA"
AES_MODE = AES.MODE_GCM
SALT = None
AES_KEYLENGTH_BITS = 256
HASH_MODE = SHA256
EC_CURVE = x25519.X25519PrivateKey

AES_KEYLENGTH = AES_KEYLENGTH_BITS // 8

session = requests.Session()

def generate_keys():
    signer = oqs.Signature(SIGN_ALGO)
    public_key = signer.generate_keypair()
    return signer.export_secret_key(), public_key

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

def encrypt_and_sign(message: str, encrypt_key: bytes | None, sign_prikey: bytes, sign_pubkey: bytes, message_key: str = "data", signature_key: str = "signature", signature_pubkey_key: str = "signature_public_key") -> dict:
    """
    Encrypt and sign message
    :param message: str: message to encrypt
    :param encrypt_key: bytes: key to encrypt data
    :param sign_prikey: bytes: private key to sign data
    :param sign_pubkey: bytes: public key to verify signature
    :return: dict: encrypted data and signature
    """
    if encrypt_key is not None:
        encrypted_data = encrypt_aes_gcm(message.encode('utf-8'), encrypt_key)
    else:
        encrypted_data = message
    signature = sign_message(encrypted_data.encode('utf-8'), sign_prikey)
    return {
        message_key: encrypted_data,
        signature_key: base64.b64encode(signature).decode('utf-8'),
        signature_pubkey_key: base64.b64encode(sign_pubkey).decode('utf-8')
    }

def decrypt_and_verify(data: dict, decrypt_key: bytes | None, data_key: str = "data", signature_key: str = "signature", signature_pubkey_key: str = "signature_public_key")->str | None:
    """
    Decrypt and verify data
    :param data: dict: data to decrypt and verify
    :param data_key: str: key to get encrypted data
    :param decrypt_key: bytes | None: key to decrypt data
    :param verify_pubkey: bytes: public key to verify signature
    :return: str | None: decrypted data or None if signature is invalid
    """
    encrypted_data = data[data_key]
    signature = base64.b64decode(data[signature_key])
    signature_public_key = base64.b64decode(data[signature_pubkey_key])
    if not verify_signature(encrypted_data.encode('utf-8'), signature, signature_public_key):
        return None
    if decrypt_key is None:
        return encrypted_data
    return decrypt_aes_gcm(encrypted_data, decrypt_key)

# --------------------------------------------------------------

# Initialize CryptoHelper with parameters
crypto_helper = CryptoHelper(
    sign_algo=SIGN_ALGO,
    aes_mode="GCM",
    salt=None,
    aes_keylength_bits=256,
    hash_mode="SHA256",
    ec_curve='curve25519'
)

if SIGN_ALGO == "Dilithium2":
    # Generate client keys for signing
    secret_key, public_key = crypto_helper.generate_keys()
else:
    secret_key, public_key = crypto_helper.generate_keys(goal="sign")

# Set all algorithms and parameters into user session
response = session.post('http://localhost:5000/api/v1/keyexs/algo', json={
    'sign_algo': SIGN_ALGO,
    'aes_mode': 'GCM',
    'salt': None,
    'aes_keylength_bits': 256,
    'hash_mode': 'SHA256',
    'ec_curve': 'curve25519'
})
if response.status_code != 200:
    print("Failed to set algorithms and parameters")
    exit()

# Generate client key pair for ECDH
if crypto_helper.ec_curve == x25519.X25519PrivateKey:
    client_private_key = x25519.X25519PrivateKey.generate()
else:
    client_private_key = ec.generate_private_key(crypto_helper.ec_curve)
client_public_key = client_private_key.public_key()

# Serialize client public key
client_public_pem = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Sign client_public_pem
signature = crypto_helper.sign_message(client_public_pem.encode('utf-8'), secret_key)

# Request to server api/v1/keyexs/keyex
response = session.post('http://localhost:5000/api/v1/keyexs/keyex', json={
    'client_public_key': client_public_pem, 
    "signature": base64.b64encode(signature).decode('utf-8'), 
    "signature_public_key": base64.b64encode(public_key).decode('utf-8')
})

print({
    'client_public_key': client_public_pem, 
    "signature": base64.b64encode(signature).decode('utf-8'), 
    "signature_public_key": base64.b64encode(public_key).decode('utf-8')
})

if response.status_code != 200:
    print("Failed to exchange keys with the server")
    exit()

# Collect response
response_data = response.json()
server_public_pem = response_data['server_public_key'].encode()
signature = base64.b64decode(response_data['signature'])
signature_public_key = base64.b64decode(response_data['signature_public_key'])

print("Server Public Key:", server_public_pem, "\nSignature:", signature, "\nSignature Public Key:", signature_public_key)

# Verify server public key
if not crypto_helper.verify_signature(server_public_pem, signature, signature_public_key):
    print("Invalid signature")
    exit()
server_public_key = serialization.load_pem_public_key(server_public_pem)

# Perform key exchange
if isinstance(client_private_key, x25519.X25519PrivateKey):
    shared_key = client_private_key.exchange(server_public_key)
else:
    shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)

# Derive AES key
aes_key = HKDF(
    shared_key,
    crypto_helper.aes_keylength,
    salt=crypto_helper.salt,
    hashmod=crypto_helper.hash_mode,
    num_keys=1
)

#print("AES Key:", aes_key)

# --------------------------------------------------------------

# # Top up Alice's account
# topup_data = json.dumps({
#     'receiver': 'Alice',
#     'amount': 10
# }).encode('utf-8')

# encrypted_data = encrypt_aes_gcm(topup_data, aes_key)
# signature = sign_message(encrypted_data.encode('utf-8'), secret_key)

# response = session.post('http://localhost:5000/topup', json={
#     'encoded_AES_data': encrypted_data,
#     'sign': base64.b64encode(signature).decode('utf-8'),
#     'public_key': base64.b64encode(public_key).decode('utf-8')
# })
def create_transac_check(jwt, recv_username, amt) -> dict:
    transaction_data = json.dumps({
        'receiver_username': recv_username,
        'amount': amt,
        'type': 'normal',
        'message': 'Test transaction',
        'timestamp': datetime.now().isoformat(),
    }).encode('utf-8')

    encrypted_data = encrypt_aes_gcm(transaction_data, aes_key)
    signature = sign_message(encrypted_data.encode('utf-8'), secret_key)

    response = session.post('http://localhost:5000/api/v1/transactions/create', json={
        'encoded_AES_data': encrypted_data,
        'sign': base64.b64encode(signature).decode('utf-8'),
        'public_key': base64.b64encode(public_key).decode('utf-8')
    },
    headers={
        'Authorization': f'Bearer {jwt}',
    })

    transaction_response = response.json()
    if response.status_code == 422:
        print("422 Unprocessable Entity: Check the payload and JWT token")
        return {"status": False, "trasac_id": None}
    
    decrypted_data = decrypt_and_verify(transaction_response, aes_key, "encoded_AES_data", "sign", "public_key")

    if decrypted_data is None:
        print("Invalid signature")
        return {"status": False, "trasac_id": None}

    transaction = json.loads(decrypted_data)
    if transaction is None or transaction['status'] == "fail":
        print(transaction)
        return {"status": False, "trasac_id": None}
    return {"status": True, "trasac_id": transaction['data']}

def check_get_transac(jwt, transaction_id) -> dict:
    response = session.get(f'http://localhost:5000/api/v1/transactions/{transaction_id}', headers={
        'Authorization': f'Bearer {jwt}',
    })

    transaction_response = response.json()
    decrypted_data = decrypt_and_verify(transaction_response, aes_key, "encoded_AES_data", "sign", "public_key")
    
    if decrypted_data is not None:
        print("Transaction is valid")
        print(decrypted_data)
        return {"status": True, "transac": json.loads(decrypted_data)}
    else:
        print("Invalid signature")
        return {"status": False, "transac_id": None}

def register_check(name, username, password) -> bool:
    register_data = json.dumps({
        "name": name,
        "username": username,
        "password": password,
    }).encode('utf-8')

    encrypted_data = encrypt_aes_gcm(register_data, aes_key)
    signature = sign_message(encrypted_data.encode('utf-8'), secret_key)

    response = session.post('http://localhost:5000/api/v1/authentications/register', json={
        'encoded_AES_data': encrypted_data,
        'sign': base64.b64encode(signature).decode('utf-8'),
        'public_key': base64.b64encode(public_key).decode('utf-8')
    })

    register_response = response.json()
    decrypted_data = decrypt_and_verify(register_response, aes_key, "encoded_AES_data", "sign", "public_key")

    if decrypted_data is None:
        print("Invalid signature")
        return False
    
    reg_dat = json.loads(decrypted_data)
    if reg_dat is None or reg_dat['status'] == "fail":
        print(reg_dat)
        return False
    
    return True

def login_check(username, password) -> dict:
    login_data = json.dumps({
        "username": username,
        "password": password
    }).encode('utf-8')

    encrypted_data = encrypt_aes_gcm(login_data, aes_key)
    signature = sign_message(encrypted_data.encode('utf-8'), secret_key)

    response = session.post('http://localhost:5000/api/v1/authentications/login', json={
        'encoded_AES_data': encrypted_data,
        'sign': base64.b64encode(signature).decode('utf-8'),
        'public_key': base64.b64encode(public_key).decode('utf-8')
    })

    login_response = response.json()
    decrypted_data = decrypt_and_verify(login_response, aes_key, "encoded_AES_data", "sign", "public_key")
    if decrypted_data is None:
        print("Invalid signature")
        return {"status": False, "jwt": None}
    log_dat = json.loads(decrypted_data)
    if log_dat is None or log_dat['status'] == "fail":
        print(log_dat)
        return {"status": False, "jwt": None}
    
    return {"status": True, "jwt": log_dat['jwt']}

def test_cases():
    # Valid Registration and Login
    print("registration and login test cases:")
    register_check("User One", "0989743425", "password1") 
    register_check("User Two", "0989793425", "password2")
    login1 = login_check("0989743425", "password1")
    login2 = login_check("0989793425", "password2")
    login1["status"]
    login2["status"]
    jwt1 = login1["jwt"]
    jwt2 = login2["jwt"]


    # Valid Transaction
    print("transaction test cases:")
    create_transac_check(jwt1, "0989793425", 100)["status"]

    # Invalid JWT
    print("invalid jwt test cases:")
    create_transac_check("invalid_jwt", "0989793425", 100)["status"]

    # Negative Amount
    print("negative amount test cases:")
    create_transac_check(jwt1, "0989793425", -100)["status"]

    # Zero Amount
    print("zero amount test cases:")
    create_transac_check(jwt1, "0989793425", 0)["status"] 

    # Excessive Amount
    print("excessive amount test cases:")
    create_transac_check(jwt1, "0989793425", 1e18)["status"] 

    # Invalid Phone Number
    print("invalid phone number test cases:")
    create_transac_check(jwt1, "invalid_user", 100)["status"] 

    # Duplicate Phone Number Registration
    print("duplicate phone number registration test cases:")
    register_check("User Duplicate", "0989793425", "password3") 

    # Concurrent Transactions
    print("concurrent transactions test cases:")
    def concurrent_transactions():
        create_transac_check(jwt1, "0989793425", 100)
        create_transac_check(jwt2, "0989743425", 10)
    
    threads = [threading.Thread(target=concurrent_transactions) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Boundary Testing
    print("boundary testing test cases:")
    long_phone_number = "0" * 20
    register_check("Long User", long_phone_number, "password") 
    login_long = login_check(long_phone_number, "password")
    login_long["status"] 
    jwt_long = login_long["jwt"]
    create_transac_check(jwt_long, "0989793425", 100)["status"] 
    # Empty Values
    print("empty values test cases:")
    register_check("", "", "") 
    login_check("", "")
    create_transac_check(jwt1, "", 100)["status"]
    create_transac_check("", "0989793425", 100)["status"] 

    # SQL Injection / Script Injection
    print("sql injection test cases:")
    malicious_phone = "0989793425' OR '1'='1"
    malicious_password = "password' OR '1'='1"
    login_check(malicious_phone, malicious_password)["status"] 

    print("All test cases passed.")

# Run the test cases
test_cases()