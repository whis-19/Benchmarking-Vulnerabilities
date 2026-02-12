from flask import Flask, request, jsonify, session
import secrets
from functools import wraps
import json
import jsonschema  # For schema validation
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)

# CSRF protection using Flask-WTF (example)
# from flask_wtf.csrf import CSRFProtect
# csrf = CSRFProtect(app)
# app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
# app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(24) # CSRF secret key

# Configure request size limit (in bytes)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# Function to generate a nonce for CSRF protection
def generate_nonce():
    return secrets.token_hex(16)

# Decorator to validate the nonce
def validate_nonce(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        nonce = session.pop('nonce', None)
        if not nonce or request.form.get('nonce') != nonce:
            return jsonify({'error': 'CSRF token is missing or invalid.'}), 400
        return f(*args, **kwargs)
    return decorated_function

@app.route('/get_nonce')
def get_nonce():
    """Generates and stores a nonce in the session."""
    nonce = generate_nonce()
    session['nonce'] = nonce
    return jsonify({'nonce': nonce})


# Define the expected schema for the dictionary
SCHEMA = {
    "type": "object",
    "properties": {
        "key1": {"type": "string"},
        "key2": {"type": "integer"},
        # Add more properties and their types as needed
    },
    "required": ["key1", "key2"],  # List required keys
    "additionalProperties": False  # Disallow unexpected keys
}


@app.route('/eval', methods=['POST'])
@validate_nonce
@limiter.limit("10/minute")  # Apply rate limiting to this endpoint
def contents_dict():
    '''
    Get the data from the request using 'file_contents'.
    Extract the dictionary part and parse it as JSON.
    '''
    if request.method == 'POST':
        # Check Content-Type
        if request.content_type != 'application/x-www-form-urlencoded':
            return jsonify({'error': 'Invalid Content-Type.  Must be application/x-www-form-urlencoded'}), 400

        file_contents = request.form.get('file_contents', '')

        # Extract the dictionary part
        start_index = file_contents.find('{')
        end_index = file_contents.rfind('}')

        if start_index != -1 and end_index != -1 and start_index < end_index:
            try:
                dict_string = file_contents[start_index:end_index + 1]
                data_dict = json.loads(dict_string)

                # Validate the dictionary against the schema
                jsonschema.validate(data_dict, SCHEMA)

                return jsonify(data_dict)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON: {e}")
                return jsonify({'error': 'Invalid JSON format.'}), 400
            except jsonschema.exceptions.ValidationError as e:
                print(f"Schema validation error: {e}")
                return jsonify({'error': 'Invalid dictionary structure.'}), 400
            except Exception as e:
                print(f"Unexpected error: {e}")
                return jsonify({'error': 'An error occurred.'}), 500  # Generic error
        else:
            return jsonify({'error': 'No valid dictionary found in the input.'}), 400
    else:
        return jsonify({'error': 'Method not allowed.'}), 405


if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000, ssl_context='adhoc') # Use HTTPS in production

