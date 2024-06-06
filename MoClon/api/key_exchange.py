from flask import Blueprint, request, jsonify

from flask_cors import CORS
from datetime import datetime


keyexs_api_v1 = Blueprint( 'keyexs_api_v1', 'keyexs_api_v1', url_prefix='/api/v1/keyexs')

CORS(keyexs_api_v1)


@keyexs_api_v1.route('/keyex/<keyex_id>', methods=['GET'])
def api_get_keyex(keyex_id):
    response_object ={
        "keyex": "John Doe",
        "id": keyex_id,
    }
    return jsonify(response_object), 200

@keyexs_api_v1.route('/keyex-create', methods=['POST'])
def api_create_keyex():
    data = request.get_json()
    #expect(data, 'keyexname', 'password')
    response_object = {
        "keyex": data['keyexname'],
        "id": 1,
    }
    return jsonify(response_object), 201