import hashlib
import hmac
import secrets
import json
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import time
import threading
import redis  # Import the redis library

app = Flask(__name__)
CORS(app, resources={r"/process_data": {"origins": "https://your-trusted-domain.com"}})
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"],
    storage_uri="redis://localhost:6379"
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))

ALLOWED_DATA_TYPES = {str, int, float, bool, list, dict}
MAX_JSON_DEPTH = 10
NONCE_EXPIRY_SECONDS = 60  # Nonces are valid for 60 seconds

# Redis connection (replace with your Redis configuration)
redis_client = redis.Redis(host='localhost', port=6379, db=0)


def verify_hmac(data, received_hmac, secret_key):
    hmac_obj = hmac.new(secret_key.encode('utf-8'), data, hashlib.sha256)
    expected_hmac = hmac_obj.hexdigest()
    return hmac.compare_digest(expected_hmac, received_hmac)


def safe_deserialize(data, allowed_types=ALLOWED_DATA_TYPES, max_depth=MAX_JSON_DEPTH):
    try:
        deserialized_data = json.loads(data.decode('utf-8'))

        def validate_types(obj, depth=0):
            if depth > max_depth:
                raise ValueError("Maximum JSON depth exceeded")

            if type(obj) not in allowed_types:
                raise ValueError(f"Invalid data type: {type(obj)}")
            if isinstance(obj, list):
                for item in obj:
                    validate_types(item, depth + 1)
            elif isinstance(obj, dict):
                for key, value in obj.items():
                    validate_types(value, depth + 1)

        validate_types(deserialized_data)
        return deserialized_data
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Deserialization error: {e}")


def is_valid_nonce(nonce):
    """Checks if the nonce is valid (not a replay) using Redis."""
    try:
        nonce_key = f"nonce:{nonce}"
        if redis_client.get(nonce_key):
            logging.warning(f"Replay attack detected: Nonce {nonce} already used.")
            return False  # Replay attack!

        # Set the nonce in Redis with an expiry time
        redis_client.set(nonce_key, "used", ex=NONCE_EXPIRY_SECONDS)
        return True
    except redis.exceptions.ConnectionError as e:
        logging.error(f"Error connecting to Redis: {e}")
        return False  # Treat as invalid nonce if Redis is unavailable


@app.route('/process_data', methods=['POST'])
@limiter.limit("5/minute")
def process_data():
    if not request.is_json:
        logging.warning("Received non-JSON request")
        return jsonify({"error": "Request must be JSON"}), 400

    try:
        data = request.json.get('data')
        received_hmac = request.json.get('hmac')
        nonce = request.json.get('nonce')

        if not data or not received_hmac or not nonce:
            logging.warning("Missing data, hmac, or nonce")
            return jsonify({"error": "Missing data, hmac, or nonce"}), 400

        if not is_valid_nonce(nonce):
            return jsonify({"error": "Invalid nonce (replay attack?)"}), 400

        data_bytes = data.encode('utf-8')

        if not verify_hmac(data_bytes, received_hmac, SECRET_KEY):
            logging.warning("HMAC verification failed")
            return jsonify({"error": "HMAC verification failed"}), 400

        deserialized_data = safe_deserialize(data_bytes)

        if 'field2' in deserialized_data:
            field2 = deserialized_data['field2']
            if not isinstance(field2, int) or field2 < 0 or field2 > 100:
                logging.warning(f"Invalid value for field2: {field2}")
                return jsonify({"error": "Invalid value for field2. Must be an integer between 0 and 100."}), 400

        logging.info(f"Received data: {deserialized_data}")

        return jsonify({"message": "Data processed successfully"}), 200

    except ValueError as e:
        logging.error(f"ValueError: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logging.exception("Unexpected error")
        return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

