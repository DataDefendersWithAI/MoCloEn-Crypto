
// signImplementations object to store implementations
let signImplementations = {};
let Akeys = {};
/**
 * Get the SIGN implementation for a specific signName.
 * @param {string} signName - The name of the signing algorithm.
 * @returns {Promise<Object>} The SIGN implementation.
 */

async function getSIGNImplementation(signName) {
    if (!signImplementations[signName]) {
        const deactivateWASMState = true;
        signImplementations[signName] = (await import(`./bin/pqc-sign-${signName}.js`)).default(deactivateWASMState);
    }
    return signImplementations[signName];
}


async function sign_generateKeypair() {
    try {
        const sign = await getSIGNImplementation('dilithium2');
        const { publicKey, privateKey } = await sign.keypair();
        return {
            publicKey: _arrayBufferToBase64(publicKey),
            privateKey: _arrayBufferToBase64(privateKey)
        };
    } catch (error) {
        console.error(`Error generating keypair:`, error);
        throw error;
    }
}


async function enc_generateKey() {
    try {
        const key = await window.crypto.subtle.generateKey({
            name: "AES-GCM",
            length: 256
        }, true, ['encrypt', 'decrypt']);
        return key;
    } catch (error) {
        console.error('Error generating AES key:', error);
        throw error;
    }
}

async function _generateKeys() {
    const sign_keys = await sign_generateKeypair();
    const aes_key = await enc_generateKey();
    const aes_iv = crypto.getRandomValues(new Uint8Array(12));
    Akeys = {
        "AES_SECRET": aes_key,
        "AES_IV": aes_iv,
        "SIGN_PRIVATE": sign_keys.privateKey,
        "SIGN_PUBLIC": sign_keys.publicKey
    }
}
await _generateKeys();



/**
 * Sign a message using a specific signing algorithm.
 * @param {string} signName - The name of the signing algorithm.
 * @param {string} message - The message to be signed.
 * @param {string} privateKeyBase64 - The base64 encoded private key.
 * @returns {Promise<string>} The base64 encoded signature.
 */
async function signMessage(signName, message, privateKeyBase64) {
    try {
        const sign = await getSIGNImplementation(signName);
        const privateKey = _base64ToArrayBuffer(privateKeyBase64);

        if (privateKey.byteLength !== await sign.privateKeyBytes) {
            throw new Error(`Invalid private key length: got ${privateKey.byteLength} bytes, expected ${await sign.privateKeyBytes}`);
        }

        const { signature } = await sign.sign(_utf8ToArrayBuffer(message), privateKey);

        return _arrayBufferToBase64(signature);

    } catch (error) {
        console.error(`Error signing message:`, error);
        throw error;
    }
}

/**
 * Verify a signature using a specific signing algorithm.
 * @param {string} signName - The name of the signing algorithm.
 * @param {string} message - The message to be verified.
 * @param {string} signatureBase64 - The base64 encoded signature.
 * @param {string} publicKeyBase64 - The base64 encoded public key.
 * @returns {Promise<boolean>} True if the signature is valid, otherwise false.
 */
async function verifySignature(signName, message, signatureBase64, publicKeyBase64) {
    try {
        const sign = await getSIGNImplementation(signName);
        const publicKey = _base64ToArrayBuffer(publicKeyBase64);
        const signature = _base64ToArrayBuffer(signatureBase64);

        if (publicKey.byteLength !== await sign.publicKeyBytes) {
            throw new Error(`Invalid public key length: got ${publicKey.byteLength} bytes, expected ${await sign.publicKeyBytes}`);
        }

        if (signature.byteLength > await sign.signatureBytes) {
            throw new Error(`Invalid signature length: got ${signature.byteLength} bytes, expected at most ${await sign.signatureBytes}`);
        }

        return await sign.verify(signature, _utf8ToArrayBuffer(message), publicKey);
    } catch (error) {
        console.error(`Error verifying signature:`, error);
        throw error;
    }
}

/**
 * Convert a Base64 string to an ArrayBuffer.
 * @param {string} base64 - The Base64 string.
 * @returns {ArrayBuffer} The resulting ArrayBuffer.
 */
function _base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

/**
 * Convert a UTF-8 string to an ArrayBuffer.
 * @param {string} string - The UTF-8 string.
 * @returns {ArrayBuffer} The resulting ArrayBuffer.
 */
function _utf8ToArrayBuffer(string) {
    const bytes = new Uint8Array(string.length);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = string.charCodeAt(i);
    }
    return bytes;
}

/**
 * Convert an ArrayBuffer to a Base64 string.
 * @param {ArrayBuffer} buffer - The ArrayBuffer.
 * @returns {string} The resulting Base64 string.
 */
function _arrayBufferToBase64(buffer) {
    const CHUNK_SZ = 0x8000;
    let c = [];
    for (let i = 0; i < buffer.length; i += CHUNK_SZ) {
        c.push(String.fromCharCode.apply(null, buffer.subarray(i, i + CHUNK_SZ)));
    }
    return window.btoa(c.join(''));
}

/**
 * Run the complete signing process: key generation, signing, and verification.
 * @param {string} signName - The name of the signing algorithm.
 * @param {string} message - The message to be signed.
 * @returns {Promise<Object>} The result containing publicKey, privateKey, and signature.
 */

//#######################################################


async function encrypt(string, key, iv) {
    let encoded = new TextEncoder().encode(string);
    let encrypted = await crypto.subtle.encrypt({ "name": "AES-GCM", "iv": iv }, key, encoded);
    return encrypted = { "encrypted": encrypted, "iv": iv };
}

async function decrypt(encrypted, iv, key) {
    let decrypted = await crypto.subtle.decrypt({ "name": "AES-GCM", "iv": iv }, key, encrypted);
    let decoder = new TextDecoder();
    const decoded = decoder.decode(decrypted);
    return decoded;
}

async function decrypt_and_verify(encrypted, signature, publicKeyBase64) {
    const result = await verifySignature('dilithium2', encrypted, signature, publicKeyBase64);
    if (result == false)
        return "Verification failed";
    const decrypted_message = await decrypt(encrypted, Akeys.AES_IV, Akeys.AES_SECRET);
    return decrypted_message;
}

async function encrypt_and_sign(message) {
    console.log(Akeys);
    const encypted_message = await encrypt(message, Akeys.AES_SECRET, Akeys.AES_IV);
    const result = await signMessage('dilithium2', encypted_message, Akeys.SIGN_PRIVATE);
    return {
        "encrypted": encypted_message.encrypted,
        "signature": result,
        "publicKey": Akeys.SIGN_PUBLIC,
    };
}

async function encrypt_Request(message) {
    const encypted_message = await encrypt_and_sign(message);
    return encypted_message;
}

async function decrypt_Response(encrypted, signature, publicKeyBase64) {
    const decrypted_message = await decrypt_and_verify(encrypted, signature, publicKeyBase64);
    return decrypted_message;
}

let res = await encrypt_Request(JSON.stringify({
    "message": "Hello World!",
    "role": "baddev",
    "time": "-1",
    "data": {
        "money": 10000,
    },
}));
console.log(res);
let dec = await decrypt_Response(res.encrypted, res.signature, res.publicKey);
console.log(dec);

async function performKeyExchange() {
    await window.sodium.ready;
    const sodium = window.sodium;

    // Generate client's key pair for ECDH
    const clientKeyPair = sodium.crypto_kx_keypair();

    // Serialize client's public key
    const clientPublicKey = sodium.to_base64(clientKeyPair.publicKey);

    // Sign client's public key using Ed25519
    const signKeyPair = sodium.crypto_sign_keypair();
    const signature = sodium.crypto_sign_detached(clientKeyPair.publicKey, signKeyPair.privateKey);

    // First we need to include all algorithms we use in the request
    $.ajax({
        url: 'http://localhost:5000/api/v1/keyexs/algo',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            sign_algo: "Dilithium2",
            aes_mode: "GCM",
            salt: null,
            aes_keylength_bits: 256,
            hash_mode: "SHA256",
            ec_curve: "curve25519"
        }),
        success: function(responseData) {
            console.log(responseData);

            // Send request to the server
            $.ajax({
                url: 'http://localhost:5000/api/v1/keyexs/keyex',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    client_public_key: clientPublicKey,
                    signature: sodium.to_base64(signature),
                    signature_public_key: sodium.to_base64(signKeyPair.publicKey)
                }),
                success: function(responseData) {
                    const serverPublicKey = sodium.from_base64(responseData.server_public_key);
                    const serverSignature = sodium.from_base64(responseData.signature);
                    const serverSignaturePublicKey = sodium.from_base64(responseData.signature_public_key);

                    // Verify server's signature
                    const isValid = sodium.crypto_sign_verify_detached(serverSignature, serverPublicKey, serverSignaturePublicKey);
                    if (!isValid) {
                        console.error('Invalid signature');
                        return;
                    }

                    // Perform key exchange to derive a shared key
                    const sharedKey = sodium.crypto_kx_client_session_keys(clientKeyPair.publicKey, clientKeyPair.privateKey, serverPublicKey);

                    console.log('Shared Key:', sodium.to_base64(sharedKey.sharedTx));
                },
                error: function() {
                    console.error('Failed to exchange keys with the server');
                }
            });
        },
        error: function() {
            console.error('Failed to send algorithms to the server');
        }
    });
}

performKeyExchange();

export { encrypt_Request, decrypt_Response };