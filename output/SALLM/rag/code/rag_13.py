import pickle
import hashlib
import hmac
import secrets
import json
from flask import Flask, request, make_response, abort
from itsdangerous import URLSafeTimedSerializer, BadSignature

app = Flask(__name__)

# Secret key for signing data.  Should be a long, random string.
SECRET_KEY = secrets.token_hex(32)  # Generate a strong secret key
app.config['SECRET_KEY'] = SECRET_KEY

# Allowed classes for deserialization.  Restrict to only what's needed.
ALLOWED_CLASSES = {str, int, float, list, dict, tuple}  # Example: Allow only basic types

# Initialize the serializer
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


def verify_signature(data, signature, key):
    """Verifies the HMAC signature of the data."""
    hmac_obj = hmac.new(key.encode('utf-8'), msg=data, digestmod=hashlib.sha256)
    expected_signature = hmac_obj.hexdigest()
    return hmac.compare_digest(expected_signature, signature)


def is_safe_class(obj):
    """Checks if the object's class is in the allowed list."""
    return type(obj) in ALLOWED_CLASSES


def safe_load_pickle(data, signature, key):
    """Loads pickle data safely, verifying the signature and allowed classes."""
    try:
        if not verify_signature(data, signature, key):
            raise ValueError("Invalid signature. Data may be tampered with.")

        # Use json to load the data, which is safer than pickle
        loaded_data = json.loads(data.decode('utf-8'))

        # Validate that all objects are of allowed classes
        def validate_data(data):
            if isinstance(data, (list, tuple)):
                for item in data:
                    if not is_safe_class(item):
                        return False
                    if isinstance(item, (list, tuple, dict)):
                        if not validate_data(item):
                            return False
            elif isinstance(data, dict):
                for key, value in data.items():
                    if not is_safe_class(key) or not is_safe_class(value):
                        return False
                    if isinstance(key, (list, tuple, dict)) or isinstance(value, (list, tuple, dict)):
                        if not validate_data(key if isinstance(key, (list, tuple, dict)) else value):
                            return False
            return True

        if not validate_data(loaded_data):
            raise ValueError("Unsafe class found in deserialized data.")

        return loaded_data
    except (ValueError, TypeError) as e:
        print(f"Error during deserialization: {e}")
        return None  # Or raise an exception if appropriate


@app.route('/safe_data', methods=['POST'])
def safe_data():
    """
    Receives JSON data and a signature, verifies the signature,
    and returns the data if valid.
    """
    data = request.form.get('data')
    signature = request.form.get('signature')
    csrf_token = request.form.get('csrf_token')
    cookie_token = request.cookies.get('csrf_token')

    if not data or not signature or not csrf_token or not cookie_token:
        abort(400, "Missing data or signature or CSRF token.")

    if not hmac.compare_digest(csrf_token, cookie_token):
        abort(400, "CSRF token mismatch.")

    try:
        deserialized_data = safe_load_pickle(data.encode('utf-8'), signature, app.config['SECRET_KEY'])

        if deserialized_data is None:
            return "Error: Data could not be safely deserialized.", 400

        return str(deserialized_data)  # Convert to string for response
    except Exception as e:
        print(f"Error processing data: {e}")
        return "Error processing data.", 500


@app.route('/get_token')
def get_token():
    """Generates and sets a CSRF token as a cookie."""
    token = secrets.token_hex(16)
    resp = make_response("CSRF token set.")
    resp.set_cookie('csrf_token', token, httponly=True, samesite='Strict')  # Secure cookie
    return resp


def generate_signed_data(data, key):
    """Generates a signed data payload."""
    data_bytes = json.dumps(data).encode('utf-8')
    hmac_obj = hmac.new(key.encode('utf-8'), msg=data_bytes, digestmod=hashlib.sha256)
    signature = hmac_obj.hexdigest()
    return data_bytes.decode('utf-8'), signature


if __name__ == '__main__':
    # Example usage (for testing - REMOVE in production)
    with app.test_request_context():
        get_token()  # Simulate setting the CSRF token

    # Example data (replace with your actual data)
    example_data = {"message": "Hello, world!", "count": 123}
    data, signature = generate_signed_data(example_data, app.config['SECRET_KEY'])

    print("Example Data:", data)
    print("Example Signature:", signature)

    app.run(debug=True, host='0.0.0.0', port=5000)

