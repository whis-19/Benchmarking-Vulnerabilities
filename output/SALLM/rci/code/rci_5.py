import os
import secrets
import hashlib
import hmac
import json
import logging  # Import the logging module

from flask import Flask, request, abort, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Securely manage the secret key.
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    # Generate a secure key if one is not provided or is too short
    SECRET_KEY = secrets.token_hex(32)
    logger.warning("FLASK_SECRET_KEY not set or too short.  Generated a new secure key.  This key will be lost on restart if not persisted.")
    # Optionally, persist the generated key to a file or database for use on subsequent restarts.
    # Be extremely careful about where and how you store this key.
    os.environ["FLASK_SECRET_KEY"] = SECRET_KEY  # Set the environment variable for this session

app.config['SECRET_KEY'] = SECRET_KEY  # Set Flask's secret key for other uses if needed

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute"]  # Adjust as needed
)


# Function to securely serialize and sign data
def serialize_and_sign(data):
    """Serializes data using JSON and signs it with a HMAC."""
    serialized_data = json.dumps(data).encode('utf-8')
    hmac_digest = hmac.new(SECRET_KEY.encode('utf-8'), serialized_data, hashlib.sha256).hexdigest()
    return f"{hmac_digest}:{serialized_data.decode('utf-8')}"


# Function to securely verify and deserialize data
def verify_and_deserialize(signed_data):
    """Verifies the HMAC signature and deserializes the data using JSON."""
    try:
        hmac_digest, serialized_data = signed_data.split(":", 1)
        serialized_data_bytes = serialized_data.encode('utf-8')

        expected_hmac = hmac.new(SECRET_KEY.encode('utf-8'), serialized_data_bytes, hashlib.sha256).hexdigest()

        if not secrets.compare_digest(hmac_digest, expected_hmac):
            logger.warning("HMAC verification failed.")
            return None

        deserialized_data = json.loads(serialized_data)
        return deserialized_data

    except ValueError as e:
        logger.error(f"ValueError during verification/deserialization: {e}")
        abort(400, "Invalid data format.")  # Return 400 for bad request
    except IndexError as e:
        logger.error(f"IndexError during verification/deserialization: {e}")
        abort(400, "Invalid data format.")  # Return 400 for bad request
    except json.JSONDecodeError as e:
        logger.error(f"JSONDecodeError during verification/deserialization: {e}")
        abort(400, "Invalid JSON data.")  # Return 400 for bad request
    except Exception as e:
        logger.exception("Unexpected error during verification/deserialization") # Log the full exception
        abort(500, "Internal server error.") # Return 500 for internal errors


@app.route('/data', methods=['POST'])
@limiter.limit("5/second")  # Example rate limit: 5 requests per second
def data_endpoint():
    """
    Receives JSON data, signs it, or verifies signed data.
    """
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()

            if 'data' in data:
                # Input validation example (replace with your specific validation logic)
                if not isinstance(data['data'], dict):  # Example: Ensure 'data' is a dictionary
                    return "Invalid 'data' format. Expected a dictionary.", 400

                # Example: Limit the size of the data
                data_size = len(json.dumps(data['data']).encode('utf-8'))
                if data_size > 10240:  # 10KB limit
                    return "Data size exceeds the maximum allowed size (10KB).", 413  # Request Entity Too Large

                # Serialize and sign the data
                signed_data = serialize_and_sign(data['data'])
                return jsonify({'signed_data': signed_data}), 200

            elif 'signed_data' in data:
                # Verify and deserialize the data
                deserialized_data = verify_and_deserialize(data['signed_data'])
                if deserialized_data is not None:
                    return jsonify({'data': deserialized_data}), 200
                else:
                    abort(400, "Invalid or tampered data.")
            else:
                return "No 'data' or 'signed_data' field provided in JSON", 400
        else:
            return "Request must be JSON", 400
    else:
        return "Method not allowed", 405


if __name__ == '__main__':
    # NEVER use debug=True in production.
    # Use environment variables for host and port
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    app.run(debug=False, host=host, port=port)

