from flask import Blueprint, request, jsonify
from MoClon.db import add_transaction, get_transaction

from flask_cors import CORS
from datetime import datetime


transactions_api_v1 = Blueprint( 'transactions_api_v1', 'transactions_api_v1', url_prefix='/api/v1/transactions')

CORS(transactions_api_v1)


@transactions_api_v1.route('/transaction/<transaction_id>', methods=['GET'])
def api_get_transaction(transaction_id):
    response_object ={
        "transaction": "John Doe transaction",
        "id": transaction_id,
    }
    return jsonify(response_object), 200

@transactions_api_v1.route('/transaction-create', methods=['POST'])
def api_create_transaction():
    data = request.get_json()
    # expect(data, 'transactionname', 'password')
    response_object = {
        "transaction": data['transactionname'],
        "id": 1,
    }
    return jsonify(response_object), 201