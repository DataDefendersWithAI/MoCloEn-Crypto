from flask import Flask, request, jsonify, session
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64
import uuid
import oqs

# Default configuration
SIGN_ALGO = "Dilithium2"
AES_MODE = AES.MODE_GCM
SALT = None
AES_KEYLENGTH_BITS = 256
HASH_MODE = SHA256
EC_CURVE = ec.SECP256R1

AES_KEYLENGTH = AES_KEYLENGTH_BITS // 8

# Generate Dilithium keys for signing
def generate_keys() -> tuple[bytes, bytes]:
    """
    Generate Dilithium keys for signing
    :return: tuple[bytes, bytes]: secret key and public key
    """
    signer = oqs.Signature(SIGN_ALGO)
    public_key = signer.generate_keypair()
    return signer.export_secret_key(), public_key

# Encrypt plaintext using AES-GCM
def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> str:
    """
    Encrypt plaintext using AES-GCM
    :param plaintext: bytes: plaintext to encrypt
    :param key: bytes: key to encrypt plaintext
    :return: str: encrypted data in Base64 format
    """
    cipher = AES.new(key, AES_MODE)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

# Decrypt encrypted data using AES-GCM
def decrypt_aes_gcm(encrypted_data: str, key: bytes) -> str:
    """
    Decrypt encrypted data using AES-GCM
    :param encrypted_data: str: encrypted data in Base64 format
    :param key: bytes: key to decrypt data
    :return: str: decrypted plaintext
    """
    encrypted_data = base64.b64decode(encrypted_data)
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES_MODE, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Sign message using Dilithium
def sign_message(message: bytes, secret_key: bytes) -> bytes:
    """
    Sign message using Dilithium
    :param message: bytes: message to sign
    :param secret_key: bytes: secret key to sign message
    :return: bytes: signature
    """
    signer = oqs.Signature(SIGN_ALGO, secret_key=secret_key)
    return signer.sign(message)

# Verify signature using Dilithium
def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify signature using Dilithium
    :param message: bytes: message to verify
    :param signature: bytes: signature to verify
    :param public_key: bytes: public key to verify signature
    :return: bool: True if signature is valid, False otherwise
    """
    verifier = oqs.Signature(SIGN_ALGO)
    return verifier.verify(message, signature, public_key)

# Encrypt and sign message
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

# Decrypt and verify data
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

def save_keys_to_env(secret_key, public_key):
    with open('.env', 'a') as env_file:
        env_file.write(f"\nSECRET_KEY={secret_key}\n")
        env_file.write(f"PUBLIC_KEY={public_key}\n")