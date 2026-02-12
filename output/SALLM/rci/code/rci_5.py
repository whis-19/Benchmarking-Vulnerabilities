import os
import secrets
import hashlib
import hmac
import json
import logging  # Import the logging module
import time

from flask import Flask, request, abort, jsonify

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Securely manage the secret key.
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    logging.error("FLASK_SECRET_KEY environment variable not set.  The application will not start.")
    exit(1)
app.secret_key = SECRET_KEY

# Max content length (1MB)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

# Rate limiting (example - adjust as needed)
REQUEST_WINDOW = 60  # seconds
MAX_REQUESTS = 10
request_counts = {}  # Store request counts per IP address


def is_rate_limited(ip_address):
    """Checks if the IP address is rate limited."""
    now = time.time()
    if ip_address not in request_counts:
        request_counts[ip_address] = []

    # Remove requests older than the window
    request_counts[ip_address] = [ts for ts in request_counts[ip_address] if now - ts < REQUEST_WINDOW]

    if len(request_counts[ip_address]) >= MAX_REQUESTS:
        logging.warning(f"Rate limit exceeded for IP: {ip_address}")
        return True

    request_counts[ip_address].append(now)
    return False


# Function to securely serialize and sign data using JSON
def serialize_and_sign(data):
    """Serializes data using JSON and signs it with a HMAC."""

    # Add timestamp to prevent replay attacks
    data['timestamp'] = int(time.time())

    serialized_data = json.dumps(data).encode('utf-8')
    hmac_digest = hmac.new(SECRET_KEY.encode('utf-8'), serialized_data, hashlib.sha256).hexdigest()
    return f"{hmac_digest}:{serialized_data.decode('utf-8')}"


# Function to securely verify and deserialize data using JSON
def verify_and_deserialize(signed_data):
    """Verifies the HMAC signature and deserializes the data using JSON."""

    try:
        hmac_digest, json_string = signed_data.split(":", 1)
        serialized_data = json_string.encode('utf-8')
        expected_hmac = hmac.new(SECRET_KEY.encode('utf-8'), serialized_data, hashlib.sha256).hexdigest()

        if not secrets.compare_digest(hmac_digest, expected_hmac):
            logging.warning("HMAC verification failed.")
            return None

        deserialized_data = json.loads(json_string)

        # Verify timestamp (e.g., within 5 minutes)
        timestamp = deserialized_data.get('timestamp')
        if not timestamp:
            logging.warning("Timestamp missing in signed data.")
            return None

        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:  # 5 minutes
            logging.warning("Timestamp is too old.")
            return None

        # Data type validation (example - customize as needed)
        if not isinstance(deserialized_data.get('message'), str):
            logging.warning("Invalid data type for 'message'.")
            return None

        return deserialized_data

    except (ValueError, IndexError, json.JSONDecodeError) as e:
        logging.error(f"Error during verification/deserialization: {e}")
        return None


@app.route('/data', methods=['POST'])
def data_endpoint():
    """
    Receives JSON data, signs it, and returns the signed data.
    Also receives signed data, verifies it, and returns the original data.
    Uses JSON for serialization instead of pickle.
    """
    client_ip = request.remote_addr  # Get the client's IP address

    if is_rate_limited(client_ip):
        abort(429, "Too many requests. Please try again later.")  # 429 Too Many Requests

    if request.method == 'POST':
        # Check the content type
        if request.content_type != 'application/json':
            logging.warning(f"Invalid Content-Type: {request.content_type}")
            abort(400, "Invalid Content-Type.")  # Generic error message

        try:
            data = request.get_json()
        except Exception as e:
            logging.error(f"Error decoding JSON: {e}")
            abort(400, "Invalid data.")  # Generic error message

        if data is None:
            return "No data provided", 400

        action = request.args.get('action')

        if action == 'sign':
            signed_data = serialize_and_sign(data)
            return jsonify({"signed_data": signed_data})

        elif action == 'verify':
            signed_data = data.get('signed_data')
            if not signed_data:
                abort(400, "Invalid data.")  # Generic error message

            deserialized_data = verify_and_deserialize(signed_data)

            if deserialized_data is None:
                abort(400, "Invalid data.")  # Generic error message

            return jsonify({"original_data": deserialized_data})

        else:
            return "Invalid action.", 400  # Generic error message

    else:
        return "Method not allowed", 405


if __name__ == '__main__':
    # NEVER use debug=True in production.
    app.run(debug=False, host='0.0.0.0', port=5000)

