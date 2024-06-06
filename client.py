import requests
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64
import oqs

SIGN_ALGO = "Dilithium2"
AES_MODE = AES.MODE_GCM
SALT = None
AES_KEYLENGTH_BITS = 256
HASH_MODE = SHA256
EC_CURVE = ec.SECP256R1

AES_KEYLENGTH = AES_KEYLENGTH_BITS // 8

client_private_key = ec.generate_private_key(EC_CURVE())
client_public_key = client_private_key.public_key()

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

# Generate client keys for signing
secret_key, public_key = generate_keys()

# Exchange ECDH keys with the server
client_public_pem = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Sign client_public_pem
signature = sign_message(client_public_pem.encode('utf-8'), secret_key)
# Request to server
response = session.post('http://localhost:5000/ecdh-key-exchange', json={
    'client_public_key': client_public_pem, 
    "signature": base64.b64encode(signature).decode('utf-8'), 
    "signature_public_key": base64.b64encode(public_key).decode('utf-8')
})
# Collect response
server_public_pem = response.json()['server_public_key'].encode()
signature = base64.b64decode(response.json()['signature'])
signature_public_key = base64.b64decode(response.json()['signature_public_key'])
# Verify server public key
if not verify_signature(server_public_pem, signature, signature_public_key):
    print("Invalid signature")
    exit()
server_public_key = serialization.load_pem_public_key(server_public_pem)

shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
aes_key = HKDF(shared_key, AES_KEYLENGTH, salt=SALT, hashmod=HASH_MODE, num_keys=1)

# Top up Alice's account
topup_data = json.dumps({
    'receiver': 'Alice',
    'amount': 10
}).encode('utf-8')

encrypted_data = encrypt_aes_gcm(topup_data, aes_key)
signature = sign_message(encrypted_data.encode('utf-8'), secret_key)

response = session.post('http://localhost:5000/topup', json={
    'encoded_AES_data': encrypted_data,
    'sign': base64.b64encode(signature).decode('utf-8'),
    'public_key': base64.b64encode(public_key).decode('utf-8')
})

# Create and send transaction
transaction_data = json.dumps({
    'sender': 'Alice',
    'receiver': 'Bob',
    'amount': 10
}).encode('utf-8')

encrypted_data = encrypt_aes_gcm(transaction_data, aes_key)
signature = sign_message(encrypted_data.encode('utf-8'), secret_key)

response = session.post('http://localhost:5000/transaction', json={
    'encoded_AES_data': encrypted_data,
    'sign': base64.b64encode(signature).decode('utf-8'),
    'public_key': base64.b64encode(public_key).decode('utf-8')  # Encode public key in Base64
})


# Get and verify transaction using POST method
transaction_response = response.json()

decrypted_data = decrypt_and_verify(transaction_response, aes_key, "encoded_AES_data", "sign", "public_key")

if decrypted_data is None:
    print("Invalid signature")
    exit(1)

transaction_id = json.loads(decrypted_data)['id']
print("Transaction ID:", transaction_id)
encrypted_transaction_id = encrypt_aes_gcm(str(transaction_id).encode('utf-8'), aes_key)
signature = sign_message(encrypted_transaction_id.encode('utf-8'), secret_key)

# Check transaction
response = session.post('http://localhost:5000/transaction/check', json={
    'encoded_AES_data': encrypted_transaction_id,
    'sign': base64.b64encode(signature).decode('utf-8'),
    'public_key': base64.b64encode(public_key).decode('utf-8')  # Encode public key in Base64
})
transaction_response = response.json()
decrypted_data = decrypt_and_verify(transaction_response, aes_key, "encoded_AES_data", "sign", "public_key")
if decrypted_data is not None:
    print("Transaction is valid")
    print(decrypted_data)
else:
    print("Invalid signature")
