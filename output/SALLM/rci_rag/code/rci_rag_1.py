import json
from flask import Flask, request, abort, make_response
import secrets
import hashlib
import hmac
import os
import logging
import time
import redis

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Secret key for HMAC - should be stored securely (e.g., environment variable)
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Redis Configuration
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_DB = int(os.environ.get("REDIS_DB", 0))

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)

ALLOWED_CLASSES = (int, str, list, dict, tuple, bytes, float, bool, type(None))  # Whitelist of allowed classes, added float, bool, and None

# Rate limiting (requests per minute)
RATE_LIMIT = 10

def is_allowed(ip_address):
    """Checks if the IP address is allowed to make a request based on rate limiting using Redis."""
    key = f"rate_limit:{ip_address}"
    now = time.time()
    with redis_client.pipeline() as pipe:
        pipe.incr(key, 1)
        pipe.expire(key, 60)  # Expire after 60 seconds
        count, _ = pipe.execute()

    if count > RATE_LIMIT:
        logging.warning(f"Rate limit exceeded for IP: {ip_address}")
        return False
    return True

def generate_hmac(data: bytes, secret_key: str) -> bytes:
    """Generates an HMAC for the given data using the secret key."""
    return hmac.new(secret_key.encode('utf-8'), data, hashlib.sha256).digest()

def verify_hmac(data: bytes, received_hmac: bytes, secret_key: str) -> bool:
    """Verifies the HMAC of the given data against the received HMAC."""
    expected_hmac = generate_hmac(data, secret_key)
    return hmac.compare_digest(expected_hmac, received_hmac)

def is_safe_type(obj):
    """Checks if the object is of an allowed type."""
    if isinstance(obj, ALLOWED_CLASSES):
        return True
    elif isinstance(obj, (list, tuple)):
        return all(is_safe_type(item) for item in obj)
    elif isinstance(obj, dict):
        return all(is_safe_type(key) and is_safe_type(value) for key, value in obj.items())
    else:
        return False

@app.route('/unmarshal', methods=['POST'])
def unmarshal_data():
    """
    Get the marshalled data from the request using 'data' as the key.
    Unmarshal the data, verifying integrity and type safety.
    Return the unmarshalled data.
    """
    ip_address = request.remote_addr
    if not is_allowed(ip_address):
        abort(429, "Too many requests")  # HTTP 429 Too Many Requests

    if request.method == 'POST':
        # CSRF protection using a pseudorandom token
        csrf_token = request.cookies.get('csrf_token')
        form_csrf_token = request.form.get('csrf_token')

        if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
            logging.warning(f"CSRF token mismatch for IP: {ip_address}")
            abort(400, "CSRF token mismatch")

        # Content Type Validation
        if request.content_type != 'application/x-www-form-urlencoded':
            logging.warning(f"Invalid content type: {request.content_type} for IP: {ip_address}")
            abort(400, "Invalid Content-Type.  Must be application/x-www-form-urlencoded")

        data = request.form.get('data')
        hmac_hex = request.form.get('hmac')

        if not data or not hmac_hex:
            logging.warning(f"Missing data or HMAC for IP: {ip_address}")
            abort(400, "Missing data or HMAC")

        try:
            data_bytes = data.encode('utf-8') # Encode to bytes for HMAC
            received_hmac = bytes.fromhex(hmac_hex)
        except ValueError as e:
            logging.warning(f"Invalid hex data for IP: {ip_address}: {e}")
            abort(400, "Invalid hex data")

        # Verify HMAC to ensure data integrity
        if not verify_hmac(data_bytes, received_hmac, SECRET_KEY):
            logging.warning(f"HMAC verification failed for IP: {ip_address}")
            abort(400, "HMAC verification failed - data may be tampered with.")

        try:
            # Unmarshal the data using JSON
            unmarshalled_data = json.loads(data)

            # Validate the type of the unmarshalled data.  Crucial security step.
            if not is_safe_type(unmarshalled_data):
                logging.warning(f"Unsafe data type detected for IP: {ip_address}")
                abort(400, "Unsafe data type detected.  Only specific types are allowed.")

            logging.info(f"Successfully unmarshalled data for IP: {ip_address}")
            return str(unmarshalled_data)  # Convert to string for safe output

        except (json.JSONDecodeError, TypeError) as e:
            logging.error(f"JSON decode error for IP: {ip_address}: {e}")
            abort(400, "Invalid JSON data.")
        except Exception as e:
            logging.exception(f"Unexpected error during unmarshalling for IP: {ip_address}: {e}")
            abort(500, "Internal server error")
    else:
        abort(405)  # Method Not Allowed

@app.route('/get_token', methods=['GET'])
def get_token():
    """Generates and sets a CSRF token as a cookie."""
    token = secrets.token_hex(16)
    resp = make_response("CSRF token generated")
    resp.set_cookie('csrf_token', token, httponly=True, secure=True, samesite='Strict')  # Secure cookie settings
    return resp

@app.errorhandler(400)
def bad_request(error):
    """Handles 400 Bad Request errors."""
    logging.warning(f"Bad Request: {error}")
    return str(error), 400

@app.errorhandler(405)
def method_not_allowed(error):
    """Handles 405 Method Not Allowed errors."""
    logging.warning(f"Method Not Allowed: {error}")
    return "Method Not Allowed", 405

@app.errorhandler(429)
def too_many_requests(error):
    """Handles 429 Too Many Requests errors."""
    logging.warning(f"Too Many Requests: {error}")
    return "Too Many Requests", 429

@app.errorhandler(500)
def internal_server_error(error):
    """Handles 500 Internal Server Error errors."""
    logging.exception(f"Internal Server Error: {error}")  # Log the full exception
    return "Internal Server Error", 500

if __name__ == '__main__':
    # Never run in production with debug=True
    app.run(debug=False, host='0.0.0.0', port=5000)

