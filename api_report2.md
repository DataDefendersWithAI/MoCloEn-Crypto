# API Report

This document provides an overview of the API endpoints and functionalities included in the provided Python code. The code performs various actions related to user authentication, transaction creation, and transaction verification.

## Endpoints

### 1. Register User

**Endpoint:** `POST /api/v1/authentications/register`

**Description:**

This endpoint registers a new user in the system.

**Request Payload:**

```json
{
    "name": "string",
    "username": "string",
    "password": "string"
}
```

**Response:**

- **Success:** 
- **Failure:** 

**Example Usage:**


### 2. User Login

**Endpoint:** `POST /api/v1/authentications/login`

**Description:**

This endpoint allows a user to log in to the system.

**Request Payload:**

```json
{
    "username": "string",
    "password": "string"
}
```

**Response:**

- **Success:**
- **Failure:**

**Example Usage:**



### 3. Create Transaction

**Endpoint:** `POST /api/v1/transactions/create`

**Description:**

This endpoint creates a transaction between the logged-in user and another user.

**Request Payload:**

```json
{
    "encoded_AES_data": "string",
    "sign": "string",
    "public_key": "string"
}
```

**Headers:**

```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

**Response:**

- **Success:** 
- **Failure:** 

**Example Usage:**



### 4. Check Transaction

**Endpoint:** `GET /api/v1/transactions/{transaction_id}`

**Description:**

This endpoint checks the status of a transaction by its ID.

**Headers:**

```json
{
    "Authorization": "Bearer <jwt_token>"
}
```

**Response:**

- **Success:** 
- **Failure:** 

**Example Usage:**


## Encryption and Signing

All request payloads are encrypted using AES-GCM and signed before being sent to the server. The response payloads are decrypted and verified upon reception.

## Error Handling

- **422 Unprocessable Entity:** Occurs when the payload or JWT token is invalid.
- **Invalid Signature:** Occurs when the signature verification fails.
