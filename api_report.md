Here's a detailed API report for both request and response, including the type of each parameter. This report combines the server-side routes and the corresponding client-side calls.

### 1. ECDH Key Exchange

**Endpoint:** `/ecdh-key-exchange`

**Method:** `POST`

#### Request

```json
{
    "client_public_key": "string (PEM encoded public key)",
    "signature": "string (Base64 encoded signature)",
    "signature_public_key": "string (Base64 encoded public key)"
}
```

- `client_public_key`: PEM encoded public key of the client (string).
- `signature`: Base64 encoded signature of the `client_public_key` (string).
- `signature_public_key`: Base64 encoded public key used to verify the signature (string).

#### Response

```json
{
    "server_public_key": "string (PEM encoded public key)",
    "signature": "string (Base64 encoded signature)",
    "signature_public_key": "string (Base64 encoded public key)"
}
```

- `server_public_key`: PEM encoded public key of the server (string).
- `signature`: Base64 encoded signature of the `server_public_key` (string).
- `signature_public_key`: Base64 encoded public key used to verify the signature (string).

### 2. Top Up

**Endpoint:** `/topup`

**Method:** `POST`

#### Request

```json
{
    "encoded_AES_data": "string (Base64 encoded encrypted data)",
    "sign": "string (Base64 encoded signature)",
    "public_key": "string (Base64 encoded public key)"
}
```

- `encoded_AES_data`: Base64 encoded encrypted data containing top-up information (string).
- `sign`: Base64 encoded signature of the `encoded_AES_data` (string).
- `public_key`: Base64 encoded public key used to verify the signature (string).

**Decrypted Data Structure:**

```json
{
    "receiver": "string",
    "amount": "integer"
}
```

- `receiver`: The receiver of the top-up (string).
- `amount`: The amount to top up (integer).

#### Response

```json
{
    "data": "string (Base64 encoded encrypted response)",
    "signature": "string (Base64 encoded signature)",
    "signature_public_key": "string (Base64 encoded public key)"
}
```

- `data`: Base64 encoded encrypted response data (string).
- `signature`: Base64 encoded signature of the response data (string).
- `signature_public_key`: Base64 encoded public key used to verify the signature (string).

**Decrypted Data Structure:**

```json
{
    "balance": "integer",
    "status": "string"
}
```

- `balance`: Updated balance of the receiver (integer).
- `status`: Status of the top-up operation (string).

### 3. Create Transaction

**Endpoint:** `/transaction`

**Method:** `POST`

#### Request

```json
{
    "encoded_AES_data": "string (Base64 encoded encrypted data)",
    "sign": "string (Base64 encoded signature)",
    "public_key": "string (Base64 encoded public key)"
}
```

- `encoded_AES_data`: Base64 encoded encrypted data containing transaction information (string).
- `sign`: Base64 encoded signature of the `encoded_AES_data` (string).
- `public_key`: Base64 encoded public key used to verify the signature (string).

**Decrypted Data Structure:**

```json
{
    "sender": "string",
    "receiver": "string",
    "amount": "integer",
    "message": "string (optional)"
}
```

- `sender`: The sender of the transaction (string).
- `receiver`: The receiver of the transaction (string).
- `amount`: The amount to transfer (integer).
- `message`: Optional message for the transaction (string).

#### Response

```json
{
    "encoded_AES_data": "string (Base64 encoded encrypted data)",
    "sign": "string (Base64 encoded signature)",
    "public_key": "string (Base64 encoded public key)"
}
```

- `encoded_AES_data`: Base64 encoded encrypted response data (string).
- `sign`: Base64 encoded signature of the response data (string).
- `public_key`: Base64 encoded public key used to verify the signature (string).

**Decrypted Data Structure:**

```json
{
    "id": "string (UUID)",
    "timestamp": "string (ISO 8601 format)",
    "status": "string",
    "message": "string"
}
```

- `id`: Unique identifier for the transaction (UUID string).
- `timestamp`: Timestamp of the transaction (ISO 8601 string).
- `status`: Status of the transaction (string).
- `message`: Message associated with the transaction (string).

### 4. Check Transaction

**Endpoint:** `/transaction/check`

**Method:** `POST`

#### Request

```json
{
    "encoded_AES_data": "string (Base64 encoded encrypted data)",
    "sign": "string (Base64 encoded signature)",
    "public_key": "string (Base64 encoded public key)"
}
```

- `encoded_AES_data`: Base64 encoded encrypted transaction ID (string).
- `sign`: Base64 encoded signature of the `encoded_AES_data` (string).
- `public_key`: Base64 encoded public key used to verify the signature (string).

**Decrypted Data Structure:**

```json
{
    "transaction_id": "string (UUID)"
}
```

- `transaction_id`: Unique identifier for the transaction (UUID string).

#### Response

```json
{
    "encoded_AES_data": "string (Base64 encoded encrypted data)",
    "sign": "string (Base64 encoded signature)",
    "public_key": "string (Base64 encoded public key)"
}
```

- `encoded_AES_data`: Base64 encoded encrypted response data (string).
- `sign`: Base64 encoded signature of the response data (string).
- `public_key`: Base64 encoded public key used to verify the signature (string).

**Decrypted Data Structure:**

```json
{
    "id": "string (UUID)",
    "timestamp": "string (ISO 8601 format)",
    "status": "string",
    "message": "string",
    "sender": "string",
    "receiver": "string",
    "amount": "integer"
}
```

- `id`: Unique identifier for the transaction (UUID string).
- `timestamp`: Timestamp of the transaction (ISO 8601 string).
- `status`: Status of the transaction (string).
- `message`: Message associated with the transaction (string).
- `sender`: The sender of the transaction (string).
- `receiver`: The receiver of the transaction (string).
- `amount`: The amount transferred (integer).