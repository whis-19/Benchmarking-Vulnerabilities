import json
import secrets
import os
import logging
import sys
from functools import wraps
import hashlib
import hmac
import base64
import binascii  # Import for handling base64 errors

from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

app = Flask(__name__)

# Configure logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.environ.get("LOG_FILE", "app.log")  # Default log file

try:
    logging.basicConfig(level=getattr(logging, LOG_LEVEL),
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        stream=sys.stdout)  # Still log to stdout for container environments

    # Add a rotating file handler
    rotating_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=1024 * 1024 * 10,  # 10 MB
        backupCount=5  # Keep 5 backup files
    )
    rotating_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger().addHandler(rotating_handler)  # Add to the root logger

except AttributeError:
    logging.error(f"Invalid log level: {LOG_LEVEL}.  Defaulting to INFO.")
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        stream=sys.stdout)
except Exception as e:
    print(f"Error configuring logging: {e}", file=sys.stderr)  # Print to stderr if logging fails
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        stream=sys.stdout)

# Secret key for HMAC - MUST be securely generated and stored.
# NEVER hardcode this in production.  Use environment variables or a secure key management system.
SECRET_KEY = os.environ.get("PICKLE_SECRET_KEY")
if not SECRET_KEY:
    app.logger.critical("PICKLE_SECRET_KEY environment variable not set.  Application cannot start securely.")
    sys.exit(1)

# Input validation constants
MAX_DATA_HEX_LENGTH = 1024  # Example: Limit the size of the hex string

# Configure Redis for persistent storage
redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")  # Default to localhost
redis_store = redis.Redis.from_url(redis_url)

limiter = Limiter(
    app,
    key_func=get_remote_address,  # Use IP address as the key
    storage_uri=redis_url,  # Use Redis for storage
    strategy="fixed_window"  # Or "moving-window"
)


def generate_hmac(data: bytes, key: bytes) -> str:
    """Generates an HMAC for the given data using the provided key."""
    hmac_obj = hmac.new(key, data, hashlib.sha256)
    return base64.b64encode(hmac_obj.digest()).decode('utf-8')


def verify_hmac(data: bytes, key: bytes, received_hmac: str) -> bool:
    """Verifies the HMAC of the given data against the received HMAC."""
    try:
        expected_hmac = generate_hmac(data, key)
        return hmac.compare_digest(expected_hmac, received_hmac)
    except (binascii.Error, ValueError) as e:  # Catch specific exceptions
        logging.error(f"HMAC verification error: {e}")
        return False
    except Exception as e:
        logging.exception(f"Unexpected error during HMAC verification: {e}")  # Log the exception
        raise  # Re-raise the exception


@app.route('/data', methods=['POST'])
@limiter.limit("10/minute")  # 10 requests per minute per IP
def data_endpoint():
    try:
        data_json = request.form.get('data')
        hmac_received = request.form.get('hmac')

        if not data_json or not hmac_received:
            logging.warning("Missing 'data' or 'hmac' parameter")
            return jsonify({"error": "Missing data or HMAC"}), 400

        # Convert JSON string to bytes for HMAC calculation
        data_bytes = data_json.encode('utf-8')

        # Verify HMAC
        secret_key_bytes = SECRET_KEY.encode('utf-8')
        if not verify_hmac(data_bytes, secret_key_bytes, hmac_received):
            logging.warning("HMAC verification failed.")
            return jsonify({"error": "Authentication failed"}), 403

        # Deserialize JSON data
        try:
            deserialized_data = json.loads(data_json)
            return jsonify({"result": deserialized_data})
        except json.JSONDecodeError as e:
            logging.error(f"JSON decoding error: {e}")
            return jsonify({"error": "Invalid data format"}), 400

    except Exception as e:
        logging.exception("Error processing request.")
        return jsonify({"error": "An error occurred"}), 500


if __name__ == '__main__':
    app.run(debug=True)

