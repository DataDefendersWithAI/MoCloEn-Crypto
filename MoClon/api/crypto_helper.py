from flask import Flask, request, session,current_app
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, SHA512, SHA3_256, SHA3_512
from cryptography.hazmat.primitives.asymmetric import ec, x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey, EllipticCurvePublicKey
import base64
import oqs
import json

class CryptoHelper:
    def __init__(self, sign_algo="Dilithium2", aes_mode="GCM", salt=None, aes_keylength_bits=256, hash_mode="SHA256", ec_curve="curve25519"):
        self.sign_algo = sign_algo
        self.aes_mode = self.get_aes_mode(aes_mode)
        self.salt = salt
        self.aes_keylength_bits = aes_keylength_bits
        self.hash_mode = self.get_hash_mode(hash_mode)
        self.ec_curve = self.get_ec_curve(ec_curve)
        self.aes_keylength = self.aes_keylength_bits // 8

    def get_aes_mode(self, mode_name: str):
        """
        Get the AES mode based on its name.
        :param mode_name: str: name of the AES mode
        :return: AES mode
        """
        modes = {
            "GCM": AES.MODE_GCM,
            "CBC": AES.MODE_CBC,
            "CFB": AES.MODE_CFB,
            "OFB": AES.MODE_OFB,
        }
        mode = modes.get(mode_name.upper())
        if mode is None:
            raise ValueError(f"Unsupported AES mode: {mode_name}")
        return mode

    def get_hash_mode(self, hash_name: str):
        """
        Get the hash mode based on its name.
        :param hash_name: str: name of the hash mode
        :return: Hash mode
        """
        hashes = {
            "SHA256": SHA256,
            # Add other hash algorithms here if needed
            "SHA3_256": SHA3_256,
            "SHA3_512": SHA3_512,
            "SHA512": SHA512,
        }
        hash_mode = hashes.get(hash_name.upper())
        if hash_mode is None:
            raise ValueError(f"Unsupported hash mode: {hash_name}")
        return hash_mode

    def get_ec_curve(self, curve_name: str):
        """
        Get the elliptic curve class based on its name.
        :param curve_name: str: name of the elliptic curve
        :return: EllipticCurve: elliptic curve class
        """
        curves = {
            "secp256r1": ec.SECP256R1(),
            "secp256k1": ec.SECP256K1(),
            "secp384r1": ec.SECP384R1(),
            "secp521r1": ec.SECP521R1(),
            "curve25519": x25519.X25519PrivateKey,
        }
        curve = curves.get(curve_name.lower())
        if curve is None:
            raise ValueError(f"Unsupported elliptic curve: {curve_name}")
        return curve

    def generate_keys(self, goal="exchange") -> tuple[bytes, bytes]:
        """
        Generate keys for signing based on the specified algorithm.
        :return: tuple[bytes, bytes]: secret key and public key
        """
        if "Dilithium" in self.sign_algo:
            signer = oqs.Signature(self.sign_algo)
            public_key = signer.generate_keypair()
            return signer.export_secret_key(), public_key
        elif "EC" in self.sign_algo:
            if self.ec_curve == x25519.X25519PrivateKey:
                if goal == "exchange":
                    private_key = x25519.X25519PrivateKey.generate()
                    public_key = private_key.public_key()
                elif goal == "sign":
                    private_key = ed25519.Ed25519PrivateKey.generate()
                    public_key = private_key.public_key()
                else:
                    raise ValueError("Unsupported goal")
            else:
                private_key = ec.generate_private_key(self.ec_curve())
                public_key = private_key.public_key()
            return (
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            )
        else:
            raise ValueError("Unsupported signing algorithm")

    def encrypt_aes_gcm(self, plaintext: bytes, key: bytes) -> str:
        """
        Encrypt plaintext using AES-GCM
        :param plaintext: bytes: plaintext to encrypt
        :param key: bytes: key to encrypt plaintext
        :return: str: encrypted data in Base64 format
        """
        cipher = AES.new(key, self.aes_mode)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt_aes_gcm(self, encrypted_data: str, key: bytes) -> str:
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
        cipher = AES.new(key, self.aes_mode, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def sign_message(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign message using the specified algorithm.
        :param message: bytes: message to sign
        :param secret_key: bytes: secret key to sign message
        :return: bytes: signature
        """
        if "Dilithium" in self.sign_algo:
            signer = oqs.Signature(self.sign_algo, secret_key=secret_key)
            return signer.sign(message)
        elif "ECDSA" in self.sign_algo:
            private_key = serialization.load_pem_private_key(secret_key, password=None)
            if self.ec_curve == x25519.X25519PrivateKey:
                signature = private_key.sign(message)
            else:
                signature = private_key.sign(message, ECDSA(hashes.SHA256()))
            return signature
        else:
            raise ValueError("Unsupported signing algorithm")

    def verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify signature using the specified algorithm.
        :param message: bytes: message to verify
        :param signature: bytes: signature to verify
        :param public_key: bytes: public key to verify signature
        :return: bool: True if signature is valid, False otherwise
        """
        if "Dilithium" in self.sign_algo:
            verifier = oqs.Signature(self.sign_algo)
            return verifier.verify(message, signature, public_key)
        elif "ECDSA" in self.sign_algo:
            public_key = serialization.load_pem_public_key(public_key)
            try:
                if self.ec_curve == x25519.X25519PrivateKey:
                    public_key.verify(signature, message)
                else:
                    public_key.verify(signature, message, ECDSA(hashes.SHA256()))
                return True
            except Exception as e:
                return False
        else:
            raise ValueError("Unsupported signing algorithm")

    def encrypt_and_sign(self, message: str, encrypt_key: bytes | None, sign_prikey: bytes, sign_pubkey: bytes, message_key: str = "data", signature_key: str = "signature", signature_pubkey_key: str = "signature_public_key") -> dict:
        """
        Encrypt and sign message
        :param message: str: message to encrypt
        :param encrypt_key: bytes: key to encrypt data
        :param sign_prikey: bytes: private key to sign data
        :param sign_pubkey: bytes: public key to verify signature
        :return: dict: encrypted data and signature
        """
        if encrypt_key is not None:
            encrypted_data = self.encrypt_aes_gcm(message.encode('utf-8'), encrypt_key)
        else:
            encrypted_data = message
        signature = self.sign_message(encrypted_data.encode('utf-8'), sign_prikey)
        return {
            message_key: encrypted_data,
            signature_key: base64.b64encode(signature).decode('utf-8'),
            signature_pubkey_key: base64.b64encode(sign_pubkey).decode('utf-8')
        }

    def decrypt_and_verify(self, data: dict, decrypt_key: bytes | None, data_key: str = "data", signature_key: str = "signature", signature_pubkey_key: str = "signature_public_key") -> str | None:
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
        if not self.verify_signature(encrypted_data.encode('utf-8'), signature, signature_public_key):
            return None
        if decrypt_key is None:
            return encrypted_data
        return self.decrypt_aes_gcm(encrypted_data, decrypt_key)

    def save_keys_to_env(self, secret_key, public_key):
        with open('.env', 'a') as env_file:
            env_file.write(f"\nSECRET_KEY={secret_key}\n")
            env_file.write(f"PUBLIC_KEY={public_key}\n")

    def check_valid_sign_key(self, secret_key, public_key):
        try:
            if not self.verify_signature(b"test", self.sign_message(b"test", secret_key), public_key):
                return False
        except:
            return False
        return True
    
    def encrypt_response(self, response_data:dict) -> dict:
        response = response_data
        aes_key = session.get('aes_key')
            # Get secret key and public key from config, remember to client-friendly with ECDSA key
        secret_key = current_app.config['SECRET_KEY']
        public_key = current_app.config['PUBLIC_KEY']
        if session['sign_algo'] == 'ECDSA':
            secret_key = current_app.config['SECRET_KEY_EC']
            public_key = current_app.config['PUBLIC_KEY_EC']
        # Encrypt and sign the response
        encrypted_response = self.encrypt_and_sign(json.dumps(response), aes_key, secret_key, public_key, 'encoded_AES_data', 'sign', 'public_key')
        return encrypted_response


    def decrypt_request(self, data:dict ) -> dict| None:
        # Check if the user has aes_key
        aes_key = session.get('aes_key')
        if aes_key is None:
            # Redirect to /api/v1/keyexs/keyex to perform key exchange
            return {'error': 'No AES key in session. Please redirect to /api/v1/keyexs/keyex to create'}
        # Decrypt and verify the data
        decrypted_data = self.decrypt_and_verify(data, aes_key, 'encoded_AES_data', 'sign', 'public_key')
        if decrypted_data is None:
            return {'error': 'Invalid signature'}
        
        return json.loads(decrypted_data) 
        ## End secure data retrieval ---------------------------


# Others functions
def hashText(text, salt) -> str:
    """
        Basic hashing function for a text using random unique salt.  
    """
    hash1 = SHA256.new(data = salt.encode() + text.encode() ).hexdigest()
    pepper = current_app.config['PEPPER']
    hash2 = SHA3_256.new(data = pepper.encode() + hash1.encode()).hexdigest()
    return hash2
    
def matchHashedText(hashedText, providedText , salt)->bool:
    """
        Check for the text in the hashed text
    """
    hashes = hashText(providedText, salt)
    return hashedText == hashes

def decryptRequest(request : dict) -> dict | None:
    # My work: Create CryptoHelper object with params from session --------------------------
    # Check if user has all params in session
    if 'sign_algo' not in session or 'aes_mode' not in session \
        or 'salt' not in session or 'aes_keylength_bits' not in session \
        or 'hash_mode' not in session or 'ec_curve' not in session:
        return {'error': 'Missing parameters in session. Please redirect to /api/v1/keyexs/algo to create'}

    if not request or 'encoded_AES_data' not in request or 'sign'not in request or 'public_key' not in request:
        return {'error': 'Missing parameters. Invalid payload.'}

    crypto_helper = CryptoHelper(
        sign_algo=session['sign_algo'],
        aes_mode=session['aes_mode'],
        salt=session['salt'],
        aes_keylength_bits=session['aes_keylength_bits'],
        hash_mode=session['hash_mode'],
        ec_curve=session['ec_curve']
    )

    return crypto_helper.decrypt_request(request)

def encryptResponse(response : dict) -> dict:
    # My work: Create CryptoHelper object with params from session --------------------------
    # Check if user has all params in session
    if 'sign_algo' not in session or 'aes_mode' not in session \
        or 'salt' not in session or 'aes_keylength_bits' not in session \
        or 'hash_mode' not in session or 'ec_curve' not in session:
        return {'error': 'Missing parameters in session. Please redirect to /api/v1/keyexs/algo to create'}

    crypto_helper = CryptoHelper(
        sign_algo=session['sign_algo'],
        aes_mode=session['aes_mode'],
        salt=session['salt'],
        aes_keylength_bits=session['aes_keylength_bits'],
        hash_mode=session['hash_mode'],
        ec_curve=session['ec_curve']
    )

    return crypto_helper.encrypt_response(response)