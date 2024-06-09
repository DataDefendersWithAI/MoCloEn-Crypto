
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



// /**
//  * Sign a message using a specific signing algorithm.
//  * @param {string} signName - The name of the signing algorithm.
//  * @param {string} message - The message to be signed.
//  * @param {string} privateKeyBase64 - The base64 encoded private key.
//  * @returns {Promise<string>} The base64 encoded signature.
//  */
// async function signMessage(signName, messageBase64, privateKeyBase64) {
//     try {
//         const sign = await getSIGNImplementation(signName);
//         const privateKey = _base64ToArrayBuffer(privateKeyBase64);
//         const messageBuffer = _base64ToArrayBuffer(messageBase64);

//         if (privateKey.byteLength !== await sign.privateKeyBytes) {
//             throw new Error(`Invalid private key length: got ${privateKey.byteLength} bytes, expected ${await sign.privateKeyBytes}`);
//         }

//         const { signature } = await sign.sign(messageBuffer, privateKey);

//         return _arrayBufferToBase64(signature);

//     } catch (error) {
//         console.error(`Error signing message:`, error);
//         throw error;
//     }
// }

// /**
//  * Verify a signature using a specific signing algorithm.
//  * @param {string} signName - The name of the signing algorithm.
//  * @param {string} message - The message to be verified.
//  * @param {string} signatureBase64 - The base64 encoded signature.
//  * @param {string} publicKeyBase64 - The base64 encoded public key.
//  * @returns {Promise<boolean>} True if the signature is valid, otherwise false.
//  */
// async function verifySignature(signName, messageBase64, signatureBase64, publicKeyBase64) {
//     try {
//         const sign = await getSIGNImplementation(signName);
//         const publicKey = _base64ToArrayBuffer(publicKeyBase64);
//         const signature = _base64ToArrayBuffer(signatureBase64);
//         const messageBuffer = _base64ToArrayBuffer(messageBase64);

//         if (publicKey.byteLength !== await sign.publicKeyBytes) {
//             throw new Error(`Invalid public key length: got ${publicKey.byteLength} bytes, expected ${await sign.publicKeyBytes}`);
//         }

//         if (signature.byteLength > await sign.signatureBytes) {
//             throw new Error(`Invalid signature length: got ${signature.byteLength} bytes, expected at most ${await sign.signatureBytes}`);
//         }

//         return await sign.verify(signature, messageBuffer, publicKey);
//     } catch (error) {
//         console.error(`Error verifying signature:`, error);
//         throw error;
//     }
// }


// function _arrayBufferToBase64(buffer) {
//     let binary = '';
//     const bytes = new Uint8Array(buffer);
//     const len = bytes.byteLength;
//     for (let i = 0; i < len; i++) {
//         binary += String.fromCharCode(bytes[i]);
//     }
//     return window.btoa(binary);
// }

// function _base64ToArrayBuffer(base64) {
//     const binaryString = window.atob(base64);
//     const len = binaryString.length;
//     const bytes = new Uint8Array(len);
//     for (let i = 0; i < len; i++) {
//         bytes[i] = binaryString.charCodeAt(i);
//     }
//     return bytes.buffer;
// }

// /**
//  * Run the complete signing process: key generation, signing, and verification.
//  * @param {string} signName - The name of the signing algorithm.
//  * @param {string} message - The message to be signed.
//  * @returns {Promise<Object>} The result containing publicKey, privateKey, and signature.
//  */

// //#######################################################


// async function encrypt(string, key, iv) {
//     let encoded = new TextEncoder().encode(string);
//     let encrypted = await crypto.subtle.encrypt({ "name": "AES-GCM", "iv": iv }, key, encoded);
//     return { "encrypted": encrypted, "iv": iv };
// }

// async function decrypt(encrypted, iv, key) {
//     let decrypted = await crypto.subtle.decrypt({ "name": "AES-GCM", "iv": iv }, key, encrypted);
//     let decoder = new TextDecoder();
//     let decoded = decoder.decode(decrypted);
//     return decoded;
// }

// async function decrypt_and_verify(encryptedBase64, signatureBase64, publicKeyBase64) {
//     let result = await verifySignature('dilithium2', encryptedBase64, signatureBase64, publicKeyBase64);
//     if (result === false)
//         return "Signature verification failed!";
//     let encoded = _base64ToArrayBuffer(encrypted);
//     let decrypted_message = await decrypt(encoded, Akeys.AES_IV, Akeys.AES_SECRET);
//     return decrypted_message;
// }

// async function encrypt_and_sign(message) {
//     let encrypted_message = await encrypt(message, Akeys.AES_SECRET, Akeys.AES_IV);
//     let encrypted_data = _arrayBufferToBase64(encrypted_message.encrypted);
//     let sign = await signMessage('dilithium2', encrypted_data, Akeys.SIGN_PRIVATE);

//     return {
//         'encoded_AES_data': encrypted_data,
//         'sign': sign,
//         'public_key': Akeys.SIGN_PUBLIC,
//     }
// }


// let res = await encrypt_and_sign(JSON.stringify({
//     "message": "Hello World!",
//     "role": "baddev",
//     "time": "-1",
//     "data": {
//         "money": 10000,
//     },
// }));
// console.log(res);
// let dec = await decrypt_and_verify(res.encoded_AES_data, res.sign, res.public_key);
// console.log(dec);

async function signMessage(signName, messageBase64, privateKeyBase64) {
    try {
        const sign = await getSIGNImplementation(signName);
        const privateKey = _base64ToArrayBuffer(privateKeyBase64);
        const messageBuffer = _base64ToArrayBuffer(messageBase64);

        console.log(`Signing with private key length: ${privateKey.byteLength}`);
        console.log(`Message buffer length: ${messageBuffer.byteLength}`);

        if (privateKey.byteLength !== await sign.privateKeyBytes) {
            throw new Error(`Invalid private key length: got ${privateKey.byteLength} bytes, expected ${await sign.privateKeyBytes}`);
        }

        const { signature } = await sign.sign(messageBuffer, privateKey);

        const signatureBase64 = _arrayBufferToBase64(signature);
        console.log(`Generated signature: ${signatureBase64}`);
        return signatureBase64;

    } catch (error) {
        console.error(`Error signing message:`, error);
        throw error;
    }
}

async function verifySignature(signName, messageBase64, signatureBase64, publicKeyBase64) {
    try {
        const sign = await getSIGNImplementation(signName);
        const publicKey = _base64ToArrayBuffer(publicKeyBase64);
        const signature = _base64ToArrayBuffer(signatureBase64);
        const messageBuffer = _base64ToArrayBuffer(messageBase64);

        console.log(`Verifying with public key length: ${publicKey.byteLength}`);
        console.log(`Signature length: ${signature.byteLength}`);
        console.log(`Message buffer length: ${messageBuffer.byteLength}`);

        if (publicKey.byteLength !== await sign.publicKeyBytes) {
            throw new Error(`Invalid public key length: got ${publicKey.byteLength} bytes, expected ${await sign.publicKeyBytes}`);
        }

        if (signature.byteLength > await sign.signatureBytes) {
            throw new Error(`Invalid signature length: got ${signature.byteLength} bytes, expected at most ${await sign.signatureBytes}`);
        }

        const verificationResult = await sign.verify(signature, messageBuffer, publicKey);
        console.log(`Verification result: ${verificationResult}`);
        return verificationResult;
    } catch (error) {
        console.error(`Error verifying signature:`, error);
        throw error;
    }
}

function _arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function _base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

async function encrypt(string, key, iv) {
    const encoded = new TextEncoder().encode(string);
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, encoded);
    return { encrypted: encrypted, iv: iv };
}

async function decrypt(encrypted, iv, key) {
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, encrypted);
    const decoder = new TextDecoder();
    const decoded = decoder.decode(decrypted);
    return decoded;
}

async function decrypt_and_verify(encryptedBase64, signatureBase64, publicKeyBase64) {
    const verificationResult = await verifySignature('dilithium2', encryptedBase64, signatureBase64, publicKeyBase64);
    if (!verificationResult) {
        return "Signature verification failed!";
    }
    const encoded = _base64ToArrayBuffer(encryptedBase64);
    const decryptedMessage = await decrypt(encoded, Akeys.AES_IV, Akeys.AES_SECRET);
    return decryptedMessage;
}

async function encrypt_and_sign(message) {
    const encryptedMessage = await encrypt(message, Akeys.AES_SECRET, Akeys.AES_IV);
    const encryptedData = _arrayBufferToBase64(encryptedMessage.encrypted);
    const signature = await signMessage('dilithium2', encryptedData, Akeys.SIGN_PRIVATE);

    return {
        encoded_AES_data: encryptedData,
        sign: signature,
        public_key: Akeys.SIGN_PUBLIC,
    };
}

// Example usage
(async () => {
    const message = JSON.stringify({
        message: "Hello World!",
        role: "baddev",
        time: "-1",
        data: {
            money: 10000,
        },
    });

    const res = await encrypt_and_sign(message);
    console.log("Encrypted and signed data:", res);

    const dec = await decrypt_and_verify(res.encoded_AES_data, res.sign, res.public_key);
    console.log("Decrypted message:", dec);
})().catch(error => {
    console.error("Error in example usage:", error);
});



let ajaxHandler = {}

ajaxHandler.login = async function (username, password) {
    message = await encrypt_and_sign(JSON.stringify({
        "username": username,
        "password": password,
    }));
    // Send AJAX request to backend at /todo/group/create to add group
    return new Promise(function (resolve, reject) {
        $.ajax({
            type: "POST",
            url: "/api/v1/authentications/login",
            data: JSON.stringify(message),
            contentType: "application/json",
            dataType: "json",
            success: function (data) {
                console.log("Success");
                resolve(data);
            },
            error: function (data) {
                console.log("Error");
                reject(data);
            }
        });
    });
}

ajaxHandler.register= async function (name, username, password) {
    message = await encrypt_and_sign(JSON.stringify({
        "name": name,
        "username": username,
        "password": password,
    }));
    // Send AJAX request to backend at /todo/group/create to add group
    return new Promise(function (resolve, reject) {
        $.ajax({
            type: "POST",
            url: "/api/v1/authentications/register",
            data: JSON.stringify(message),
            contentType: "application/json",
            dataType: "json",
            success: function (data) {
                console.log("Success");
                resolve(data);
            },
            error: function (data) {
                console.log("Error");
                reject(data);
            }
        });
    });
}

ajaxHandler.transaction_create= async function (recv_username, amt) {
    message = await encrypt_and_sign(JSON.stringify({
        'receiver_username': recv_username,
        'amount': amt,
        'type': 'normal',
        'message': 'Test transaction',
        'timestamp': Date.now().toString(),
    }));
    // Send AJAX request to backend at /todo/group/create to add group
    return new Promise(function (resolve, reject) {
        $.ajax({
            type: "POST",
            url: "/api/v1/transactions/create",
            data: JSON.stringify(message),
            contentType: "application/json",
            dataType: "json",
            success: function (data) {
                console.log("Success");
                resolve(data);
            },
            error: function (data) {
                console.log("Error");
                reject(data);
            }
        });
    });
}

ajaxHandler.transaction_check= async function (transaction_id) {
    // Send AJAX request to backend at /todo/group/create to add group
    return new Promise(function (resolve, reject) {
        $.ajax({
            type: "GET",
            url: "/api/v1/transactions/"+transaction_id,
            data: JSON.stringify(message),
            contentType: "application/json",
            dataType: "json",
            success: function (data) {
                console.log("Success");
                resolve(data);
            },
            error: function (data) {
                console.log("Error");
                reject(data);
            }
        });
    });
}

export {ajaxHandler};