import pickle
import hashlib
import hmac
import secrets
import json
import os
import logging
import io

from flask import Flask, request, make_response, abort, render_template
from markupsafe import escape  # For output encoding
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Example limits
    storage_uri="memory://"  # In-memory storage for simplicity (use Redis in production)
)

# Load SECRET_KEY from environment variable
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    if app.config['ENV'] == 'production':
        logging.critical("SECRET_KEY environment variable not set in production. Aborting startup.")
        raise RuntimeError("SECRET_KEY not set in production")  # Terminate the app
    else:
        logging.warning("SECRET_KEY environment variable not set.  Generating a temporary key (INSECURE).")
        SECRET_KEY = secrets.token_hex(32)  # INSECURE - FOR DEVELOPMENT ONLY
else:
    logging.info("SECRET_KEY loaded from environment variable.")

app.config['SECRET_KEY'] = SECRET_KEY  # Flask requires this for session management (if used)

ALLOWED_CLASSES = {'str', 'int', 'float', 'list', 'dict', 'tuple'}  # Define allowed classes

def verify_signature(data, signature, secret_key):
    """Verifies the HMAC signature of the data."""
    hmac_obj = hmac.new(secret_key.encode('utf-8'), msg=data, digestmod=hashlib.sha256)
    expected_signature = hmac_obj.hexdigest()
    return hmac.compare_digest(signature, expected_signature)

def secure_loads(data, secret_key, allowed_classes=ALLOWED_CLASSES):
    """Securely deserializes data with signature verification and class restrictions."""
    try:
        signature = data[-64:].decode('utf-8')  # Assuming SHA256 HMAC, signature is 64 hex characters
        serialized_data = data[:-64]

        if not verify_signature(serialized_data, signature, secret_key):
            raise ValueError("Invalid signature. Data integrity compromised.")

        # Convert hex to bytes
        byte_data = bytes.fromhex(serialized_data.decode('utf-8'))

        # Custom Unpickler to restrict classes
        class RestrictedUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                # Explain that allowing more classes increases the attack surface and that attackers might find ways to exploit vulnerabilities in those classes.
                # Also, mention that even seemingly harmless classes can be used in unexpected ways to achieve malicious goals.
                if name not in allowed_classes:
                    logging.warning(f"Attempted to unpickle forbidden class: {name}")
                    raise pickle.UnpicklingError(f"Forbidden class: {name}")
                return getattr(__builtins__, name)

        # Input Validation: Check if the data looks like a list of integers before deserializing
        # This is a basic example and should be adapted to your specific data structure
        try:
            # Attempt to decode the byte data as JSON
            decoded_data = byte_data.decode('utf-8')
            json_data = json.loads(decoded_data)

            # Check if it's a list of integers
            if isinstance(json_data, list) and all(isinstance(item, int) for item in json_data):
                logging.info("Data looks like a list of integers. Proceeding with deserialization.")
            else:
                logging.warning("Data does not look like a list of integers. Aborting deserialization.")
                raise ValueError("Invalid data format")
        except (json.JSONDecodeError, ValueError) as e:
            logging.warning(f"Data validation failed: {e}. Aborting deserialization.")
            raise ValueError("Invalid data format")

        return RestrictedUnpickler(io.BytesIO(byte_data)).load()

    except (ValueError, TypeError, pickle.UnpicklingError) as e:
        logging.error(f"Deserialization error: {e}")
        return None  # Or raise an exception, depending on desired behavior
    except Exception as e:
        logging.exception(f"Unexpected error during deserialization: {e}")
        return None


@app.route('/unpickled', methods=['POST'])
@limiter.limit("10 per minute")  # Apply rate limiting to the endpoint
def unpickled():
    """
    Get the data from the request using 'data' as the key.
    Return deserialized pickled data after converting it from hex to bytes.
    """
    if request.method == 'POST':
        data = request.form.get('data')
        csrf_token_form = request.form.get('csrf_token')
        csrf_token_cookie = request.cookies.get('csrf_token')

        if not csrf_token_form or not csrf_token_cookie or not hmac.compare_digest(csrf_token_form, csrf_token_cookie):
            logging.warning("CSRF token mismatch")
            abort(400, description="CSRF token mismatch")

        if not data:
            logging.warning("No data provided")
            return "No data provided", 400

        try:
            # Securely deserialize the data
            unpickled_data = secure_loads(data.encode('utf-8'), SECRET_KEY)

            if unpickled_data is None:
                logging.error("Deserialization failed")
                return "Deserialization failed", 400

            response_data = escape(str(unpickled_data))  # Or return as JSON, depending on the data type, and ESCAPE!
            response = make_response(response_data)
            response.headers['Content-Type'] = 'text/plain; charset=utf-8' # Set Content-Type header

            # Set Content Security Policy (CSP) header
            response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP

            return response

        except Exception as e:
            logging.exception(f"Error during unpickling: {e}")
            return "Error processing data", 500
    else:
        return "Method not allowed", 405

@app.route('/get_token')
def get_token():
    """Generates and sets a CSRF token as a cookie."""
    csrf_token = secrets.token_hex(16)
    resp = make_response("CSRF token generated")
    resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict', secure=True)  # Secure cookie settings
    resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
    return resp

def generate_signed_data(data, secret_key):
    """Serializes data, signs it with HMAC, and returns the combined data and signature."""
    serialized_data = pickle.dumps(data)
    hex_data = serialized_data.hex().encode('utf-8')
    hmac_obj = hmac.new(secret_key.encode('utf-8'), msg=hex_data, digestmod=hashlib.sha256)
    signature = hmac_obj.hexdigest()
    return hex_data.decode('utf-8') + signature

@app.route('/')
def index():
    """Renders a form with a CSRF token."""
    csrf_token = secrets.token_hex(16)
    resp = make_response(render_template('index.html', csrf_token=csrf_token))
    resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict', secure=True)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp

# Error handler for rate limiting
@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning("Rate limit exceeded")
    return "Rate limit exceeded", 429

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)

