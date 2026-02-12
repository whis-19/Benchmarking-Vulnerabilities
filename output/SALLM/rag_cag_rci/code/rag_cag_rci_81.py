from flask import Flask, request, jsonify, session
import secrets
import os
from urllib.parse import urlparse
from marshmallow import Schema, fields, ValidationError

app = Flask(__name__)
app.secret_key = os.urandom(24)

ALLOWED_DOMAINS = ["example.com", "localhost"]

def is_valid_url(url):
    """Validates a URL against an allowlist of domains."""
    try:
        result = urlparse(url)
        return result.netloc in ALLOWED_DOMAINS and result.scheme in ['http', 'https']
    except:
        return False

def generate_nonce():
    """Generates a unique and unpredictable nonce."""
    return secrets.token_urlsafe(16)  # Use URL-safe nonce

@app.before_request
def before_request():
    """Sets a nonce in the session for CSRF protection."""
    if request.method == 'POST':
        session['nonce'] = generate_nonce()

class InputDataSchema(Schema):
    """Schema for validating the input data."""
    name = fields.Str(required=True)
    age = fields.Int(required=True, validate=lambda n: n > 0)
    # Add more fields and validation rules as needed

@app.route('/parse_string_to_dict', methods=['POST'])
def parse_string_to_dict():
    """Parses form data to a dictionary using schema validation."""
    # CSRF protection
    form_nonce = request.form.get('nonce')
    session_nonce = session.pop('nonce', None)

    if not form_nonce or form_nonce != session_nonce:
        return jsonify({"error": "CSRF token is missing or invalid."}), 400

    # Expect form data
    name = request.form.get('name')
    age = request.form.get('age')

    if not name or not age:
        return jsonify({"error": "Missing name or age parameters."}), 400

    try:
        # Manually construct the data dictionary
        data = {'name': name, 'age': int(age)}  # Convert age to integer

        validated_data = InputDataSchema().load(data)
        return jsonify(validated_data), 200
    except ValidationError as err:
        return jsonify(err.messages), 400
    except ValueError:
        return jsonify({"error": "Age must be an integer."}), 400
    except Exception as e:
        # Log the error for debugging (use proper logging in production)
        print(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500  # Generic error message

@app.route('/validate_url', methods=['POST'])
def validate_url_route():
    """Validates a URL received in the request."""
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "URL parameter is missing."}), 400

    if is_valid_url(url):
        return jsonify({"message": "URL is valid."}), 200
    else:
        return jsonify({"error": "URL is invalid or not in the allowlist."}), 400

@app.route('/get_nonce')
def get_nonce():
    """Returns a new nonce for CSRF protection."""
    nonce = generate_nonce()
    session['nonce'] = nonce
    return jsonify({'nonce': nonce})

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)  # Bind to localhost

