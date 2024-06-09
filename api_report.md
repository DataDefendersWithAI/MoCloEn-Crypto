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




### 2. Top Up (Not implemented)

**Endpoint:** `/api/v1/transactions/topup`

**Method:** `POST`

#### Request

**Request Payload:**
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


**Headers:**
```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

#### Response

**Response Payload:**
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

**Endpoint:** `/api/v1/transactions/create`

**Method:** `POST`

#### Request

**Request Payload:**
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
    "receiver_username": "string",
    "amount": "integer",
    "message": "string (optional)",
    "timestamp": "string isoformat timestamp"
}
```

- `receiver_username`: The unique identifier (phone number) of the receiver of the transaction (string).
- `amount`: The amount to transfer (integer).
- `message`: Optional message for the transaction (string).
- `timestamp`: Timestamp (string)

**Headers:**
```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

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
        "status": "success",
        "message": "Transaction created successfully",
        "data":  "transaction_id"
}
```

- `status`: Status of the transaction (string).
- `message`: Message associated with the transaction (string).
- `data`: Contains transaction id




### 4. Check Transaction

**Endpoint:** `/api/v1/transactions/{transaction_id}`

**Method:** `GET`

#### Request

**Headers:**
```json
{
    "Authorization": "Bearer <jwt_token>"
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
  "data": {
    "amount": "int",
    "receiver_username": "string",
    "sender_username": "string",
    "timestamp": "string timestamp ISO format",
    "message": "string",
    "type": "string",
    "status": "success | failed",
    "status_msg": "string",
    "transaction_id": "string"
  }
}
```

- `transaction_id`: Unique identifier for the transaction (UUID string).
- `timestamp`: Timestamp of the transaction (ISO 8601 string).
- `type`: "type of transaction (string)"
- `status`: Status of the transaction (string).
- `status_msg`: Status message of the transaction (string).
- `message`: Message associated with the transaction (string).
- `sender_username`: The sender of the transaction (string).
- `receiver_username`: The receiver of the transaction (string).
- `amount`: The amount transferred (integer).




### 5. Login credentials

**Endpoint:** `/api/v1/authentications/login`

**Method:** `POST`

#### Request

**Request Payload:**

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
    "username": "string",
    "password": "string"
}
```
 - `username`: user unique identifier (phone number) (string).
 - `password`: user password (string)


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
    "status": "success | fail",
    "message": "string",
    "jwt": "string",
}
```
- `status`: success or fail (string)
- `message`: returned message (string)
- `jwt`: returned jwt token (string)




### 5. Register credentials

**Endpoint:** `/api/v1/authentications/register`

**Method:** `POST`

#### Request

**Request Payload:**

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
    "name": "string",
    "username": "string",
    "password": "string"
}
```
 - `name` : user's name (string)
 - `username`: user unique identifier (phone number) (string).
 - `password`: user password (string)

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
    "status": "success | fail",
    "message": "string",
}
```
- `status`: success or fail (string)
- `message`: returned message (string)

