from flask import Flask, request, make_response
import hashlib
import hmac
import os
import secrets
import json

app = Flask(__name__)

# Secret key for HMAC - MUST be securely stored and managed.
# NEVER hardcode this in production.  Use environment variables or a secure vault.
SECRET_KEY = os.environ.get("HMAC_SECRET_KEY", secrets.token_hex(32))  # Fallback for local dev only

# Function to generate a secure HMAC
def generate_hmac(data: bytes, key: bytes) -> str:
    """Generates an HMAC for the given data using the provided key."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()

# Function to verify the HMAC
def verify_hmac(data: bytes, hmac_value: str, key: bytes) -> bool:
    """Verifies the HMAC against the given data and key."""
    try:
        hmac_obj = hmac.new(key, data, hashlib.sha256)
        return hmac.compare_digest(hmac_obj.hexdigest(), hmac_value)
    except Exception:
        return False

@app.route('/safe_data', methods=['POST'])
def safe_data():
    """
    Receives JSON data, verifies its integrity using HMAC, and processes it safely.
    """
    # 1. Get the data and HMAC from the request.  Expect JSON format.
    try:
        data = request.get_json()
        if not data or 'payload' not in data or 'hmac' not in data:
            return "Invalid request format.  Expected JSON with 'payload' and 'hmac' fields.", 400

        payload_str = data['payload']
        hmac_value = data['hmac']

        # Convert payload to bytes for HMAC verification
        payload_bytes = payload_str.encode('utf-8')

    except Exception as e:
        print(f"Error processing request: {e}")
        return "Error processing request.  Invalid JSON or missing fields.", 400

    # 2. Verify the HMAC.
    if not verify_hmac(payload_bytes, hmac_value, SECRET_KEY.encode('utf-8')):
        return "HMAC verification failed.  Data may be tampered with.", 403

    # 3.  Safely process the data (e.g., using json.loads).
    try:
        # Deserialize the JSON payload
        deserialized_data = json.loads(payload_str)

        # Now you can safely work with deserialized_data.  For example:
        print(f"Received data: {deserialized_data}")
        # DO NOT execute arbitrary code based on the deserialized data.
        # Instead, use a predefined schema or allowlist to validate the data
        # and only process known, safe fields.

        # Example of safe data handling:
        if isinstance(deserialized_data, dict) and "name" in deserialized_data:
            name = deserialized_data["name"]
            return f"Hello, {name}!", 200
        else:
            return "Data received successfully, but no 'name' field found.", 200

    except json.JSONDecodeError:
        return "Invalid JSON payload.", 400
    except Exception as e:
        print(f"Error processing deserialized data: {e}")
        return "Error processing deserialized data.", 500


@app.route('/get_token')
def get_token():
    """
    Generates a CSRF token and sets it as a cookie.
    """
    token = secrets.token_hex(16)  # Generate a 16-byte (32 hex character) token
    resp = make_response("CSRF token generated and set as a cookie.")
    resp.set_cookie('csrf_token', token, httponly=True, secure=True, samesite='Strict')  # Secure, HttpOnly, and Strict SameSite
    return resp

@app.route('/protected', methods=['POST'])
def protected():
    """
    A protected route that requires a valid CSRF token.
    """
    token_from_cookie = request.cookies.get('csrf_token')
    token_from_form = request.form.get('csrf_token')

    if not token_from_cookie or not token_from_form:
        return "CSRF token missing.", 400

    if not secrets.compare_digest(token_from_cookie, token_from_form):
        return "CSRF token mismatch.", 403

    # If the tokens match, process the request.
    return "Request processed successfully!", 200


if __name__ == '__main__':
    #  Never use debug mode in production.
    app.run(debug=True, host='0.0.0.0', port=5000)

