from flask import Flask, request, jsonify, make_response, session
import hashlib
import hmac
import secrets
import json
import os
import logging
from html import escape  # For HTML sanitization
from jsonschema import validate, ValidationError  # For JSON schema validation
from jsonschema import Draft7Validator  # Specify the Draft version
from flask_sslify import SSLify  # For HTTPS redirection (optional)

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'  # Or 'redis', 'mongodb', etc.
app.secret_key = os.environ.get("FLASK_SESSION_SECRET") or secrets.token_hex(24) # Secure session key
# app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit request size (16MB)

# Optional: Force HTTPS redirection
# sslify = SSLify(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Securely load the SECRET_KEY from an environment variable
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    logging.warning("SECRET_KEY not set in environment. Generating a new one. This is NOT recommended for production.")

ALLOWED_CLASSES = ['str', 'int', 'float', 'list', 'dict', 'tuple']  # Whitelist allowed classes

# Define a JSON schema for validation
DATA_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "minLength": 1, "maxLength": 100},
        "age": {"type": "integer", "minimum": 0, "maximum": 150},
        "email": {"type": "string", "format": "email"},
    },
    "required": ["name", "age", "email"],
    "additionalProperties": False,  # Disallow unexpected properties
}

def verify_signature(data, signature, secret_key):
    """Verifies the HMAC signature of the data."""
    hmac_obj = hmac.new(secret_key.encode('utf-8'), msg=data, digestmod=hashlib.sha256)
    expected_signature = hmac_obj.hexdigest()
    return hmac.compare_digest(expected_signature, signature)

def safe_deserialize(data, signature, secret_key, allowed_classes, schema):
    """Safely deserializes data after verifying its signature, type, and schema."""
    if not verify_signature(data, signature, secret_key):
        logging.warning("Invalid signature. Data integrity compromised.")
        raise ValueError("Invalid signature. Data integrity compromised.")

    try:
        # Use json instead of pickle for safer deserialization
        deserialized_data = json.loads(data.decode('utf-8'))

        # Validate the type of deserialized data
        if type(deserialized_data).__name__ not in allowed_classes:
            logging.warning(f"Disallowed class: {type(deserialized_data).__name__}")
            raise ValueError(f"Disallowed class: {type(deserialized_data).__name__}")

        # Validate against the JSON schema
        try:
            #validate(deserialized_data, schema) # Old version
            Draft7Validator(schema).validate(deserialized_data) # Specify Draft version
        except ValidationError as e:
            logging.warning(f"JSON schema validation error: {e}")
            raise ValueError(f"Invalid data format: {e}")

        return deserialized_data
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON data: {e}")
        raise ValueError("Invalid JSON data.")
    except Exception as e:
        logging.exception(f"Deserialization error: {e}")
        raise ValueError(f"Deserialization error: {e}")


@app.route('/process_data', methods=['POST'])
def process_data():
    """
    Processes data received in a JSON format, ensuring integrity and type safety.
    """
    if request.method == 'POST':
        try:
            data = request.form.get('data')
            signature = request.form.get('signature')
            csrf_token_form = request.form.get('csrf_token')

            if not data or not signature or not csrf_token_form:
                logging.warning("Missing data, signature, or CSRF token")
                return jsonify({'error': 'Missing data, signature, or CSRF token'}), 400

            csrf_token_cookie = session.get('csrf_token')  # Get from session

            if not csrf_token_cookie or not hmac.compare_digest(csrf_token_form, csrf_token_cookie):
                logging.warning("CSRF token mismatch")
                return jsonify({'error': 'CSRF token mismatch'}), 400

            deserialized_data = safe_deserialize(data.encode('utf-8'), signature, SECRET_KEY, ALLOWED_CLASSES, DATA_SCHEMA)

            # Process the deserialized data (e.g., store in a database, perform calculations)
            # **IMPORTANT: Sanitize the data before using it!**
            # Example (for database insertion - use appropriate escaping for your database):
            # sanitized_data = escape_data_for_database(deserialized_data)

            # Example of basic sanitization (HTML encoding for display):
            # from html import escape
            # sanitized_data = escape(str(deserialized_data))

            # Example of context-aware sanitization (HTML escaping for display):
            sanitized_name = escape(deserialized_data['name'])
            sanitized_age = deserialized_data['age']  # Assuming age is an integer, no HTML escaping needed
            sanitized_email = escape(deserialized_data['email'])

            result = {"message": "Data processed successfully", "data": {"name": sanitized_name, "age": sanitized_age, "email": sanitized_email}}
            logging.info("Data processed successfully")
            return jsonify(result), 200

        except ValueError as e:
            logging.error(f"ValueError: {e}")
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logging.exception(f'An unexpected error occurred: {str(e)}')
            return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500
    else:
        return jsonify({'error': 'Method not allowed'}), 405

@app.route('/get_csrf_token', methods=['GET'])
def get_csrf_token():
    """Generates and sets a CSRF token in the session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return jsonify({'csrf_token': session['csrf_token']})

# Example of a state-changing endpoint that requires CSRF protection
@app.route('/update_settings', methods=['POST'])
def update_settings():
    """Updates user settings (example). Requires CSRF protection."""
    if request.method == 'POST':
        try:
            csrf_token_form = request.form.get('csrf_token')
            if not csrf_token_form:
                logging.warning("Missing CSRF token")
                return jsonify({'error': 'Missing CSRF token'}), 400

            csrf_token_cookie = session.get('csrf_token')

            if not csrf_token_cookie or not hmac.compare_digest(csrf_token_form, csrf_token_cookie):
                logging.warning("CSRF token mismatch")
                return jsonify({'error': 'CSRF token mismatch'}), 400

            # Process the settings update (after sanitizing and validating the input)
            new_setting = request.form.get('new_setting')
            # Validate and sanitize new_setting before using it!

            logging.info("Settings updated successfully")
            return jsonify({'message': 'Settings updated successfully'}), 200

        except Exception as e:
            logging.exception(f'An unexpected error occurred: {str(e)}')
            return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500
    else:
        return jsonify({'error': 'Method not allowed'}), 405


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

