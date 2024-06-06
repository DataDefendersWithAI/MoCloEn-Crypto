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

print(response.json())

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

print(response.json())

# Get and verify transaction using POST method
transaction_id = response.json()['transaction_id']
encrypted_transaction_id = encrypt_aes_gcm(str(transaction_id).encode('utf-8'), aes_key)
signature = sign_message(encrypted_transaction_id.encode('utf-8'), secret_key)
response = session.post('http://localhost:5000/transaction/check', json={
    'encoded_AES_data': encrypted_transaction_id,
    'sign': base64.b64encode(signature).decode('utf-8'),
    'public_key': base64.b64encode(public_key).decode('utf-8')  # Encode public key in Base64
})
transaction_response = response.json()

encoded_AES_data = transaction_response['encoded_AES_data']
sign = base64.b64decode(transaction_response['sign'])
public_key = base64.b64decode(transaction_response['public_key'])  # Decode Base64 back to binary

if verify_signature(encoded_AES_data.encode('utf-8'), sign, public_key):
    decrypted_data = decrypt_aes_gcm(encoded_AES_data, aes_key)
    transaction_data = json.loads(decrypted_data)
    print(transaction_data)
else:
    print("Invalid signature")
