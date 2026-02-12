import pickle
import hmac
import hashlib
import secrets
import os
from flask import Flask, request, Response, make_response
from cryptography.fernet import Fernet

app = Flask(__name__)

# Generate a strong, random key for HMAC and Fernet encryption.  Store securely.
# In a real application, this should be stored in a secure location like a secrets manager.
# NEVER hardcode keys in your source code.
HMAC_KEY = os.environ.get("HMAC_KEY", secrets.token_bytes(32))  # Get from environment or generate
FERNET_KEY = os.environ.get("FERNET_KEY", Fernet.generate_key()) # Get from environment or generate
fernet = Fernet(FERNET_KEY)

# Generate a CSRF token for each session
def generate_csrf_token():
    return secrets.token_hex(16)

# Set CSRF token as a cookie
@app.before_request
def set_csrf_token():
    if request.endpoint != 'unpickled': # Apply CSRF protection only to the vulnerable endpoint
        return
    if request.method == 'POST':
        if not request.cookies.get('csrf_token'):
            csrf_token = generate_csrf_token()
            resp = make_response()
            resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
            return resp
    else:
        csrf_token = generate_csrf_token()
        resp = make_response()
        resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
        return resp

def verify_csrf_token():
    if request.method == 'POST':
        csrf_token_form = request.form.get('csrf_token')
        csrf_token_cookie = request.cookies.get('csrf_token')

        if not csrf_token_form or not csrf_token_cookie or csrf_token_form != csrf_token_cookie:
            return False
    return True

def verify_hmac(data, received_hmac):
    """Verifies the HMAC of the data."""
    calculated_hmac = hmac.new(HMAC_KEY, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(calculated_hmac, received_hmac)

def safe_deserialize(encrypted_data, received_hmac):
    """
    Safely deserializes data using Fernet encryption and HMAC for integrity.
    """
    if not verify_hmac(encrypted_data, received_hmac):
        raise ValueError("HMAC verification failed. Data integrity compromised.")

    try:
        decrypted_data = fernet.decrypt(encrypted_data.encode('utf-8'))
        # Instead of directly unpickling, use a safer alternative like JSON or YAML if possible.
        # If unpickling is absolutely necessary, implement restrictions on gadget chains.
        # Example: Only allow deserialization of specific classes.
        # allowed_classes = [MySafeClass, ...]
        # data = pickle.loads(decrypted_data, fix_imports=True, encoding="ASCII", errors="strict")

        # Replace the following line with a safer deserialization method if possible.
        # If not, implement gadget chain restrictions.
        data = pickle.loads(decrypted_data)  # This line is inherently dangerous.

        return data
    except Exception as e:
        raise ValueError(f"Deserialization failed: {e}")


@app.route('/unpickled_data', methods=['POST'])
def unpickled():
    """
    Receives encrypted and HMAC-protected pickled data, verifies integrity,
    decrypts, and attempts to deserialize it safely.
    """
    if not verify_csrf_token():
        return "CSRF token verification failed", 400

    encrypted_data = request.form.get('data')
    received_hmac = request.form.get('hmac')

    if not encrypted_data or not received_hmac:
        return "Missing data or HMAC", 400

    try:
        data = safe_deserialize(encrypted_data, received_hmac)
        return str(data)  # Convert to string for safe output
    except ValueError as e:
        return str(e), 400
    except Exception as e:
        # Log the error for debugging purposes.  Do NOT expose sensitive information in the error message.
        print(f"Unexpected error: {e}")
        return "An unexpected error occurred", 500


def generate_encrypted_data_with_hmac(data):
    """
    Encrypts data using Fernet and generates an HMAC for integrity.
    """
    pickled_data = pickle.dumps(data)
    encrypted_data = fernet.encrypt(pickled_data).decode('utf-8')
    hmac_value = hmac.new(HMAC_KEY, encrypted_data.encode('utf-8'), hashlib.sha256).hexdigest()
    return encrypted_data, hmac_value


if __name__ == '__main__':
    # Example usage (for testing purposes only - remove in production)
    with app.test_request_context():
        csrf_token = generate_csrf_token()
        resp = make_response()
        resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')

    # Example of creating data and encrypting it
    example_data = {"message": "This is a test", "value": 123}
    encrypted_data, hmac_value = generate_encrypted_data_with_hmac(example_data)
    print(f"Encrypted data: {encrypted_data}")
    print(f"HMAC: {hmac_value}")

    # In a real application, you would send the encrypted_data and hmac_value
    # to the client, who would then POST it to the /unpickled_data endpoint.

    app.run(debug=True, host='0.0.0.0', ssl_context='adhoc') # Use HTTPS in production!

