from flask import Flask, request, jsonify, session
import secrets
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# CSRF protection using double-submitted cookies
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            return jsonify({"error": "CSRF token missing or invalid"}), 403

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

class Tree(object):
    '''
    A tree.
    '''

    def __init__(self, root):
        '''
        Initialize the tree.

        :param root: The root node.
        '''

        self.root = root

    def get_root(self):
        '''
        Get the root node.

        :return: The root node.
        '''

        return self.root

# Example allowed domains/IPs (replace with your actual allowed list)
ALLOWED_DOMAINS = ["example.com", "127.0.0.1"]  # Example: Only allow requests from example.com and localhost

def is_valid_origin(origin):
    """
    Validates the origin of the request against an allowlist.
    """
    if not origin:
        return False

    try:
        parsed_url = urlparse(origin)
        hostname = parsed_url.hostname
        return hostname in ALLOWED_DOMAINS
    except:
        return False

@app.route('/get_value', methods=['POST'])  # Use POST for state changes
def get_value():
    '''
    Get the value for the given key from the given object by having them from the request.
    Return the value as a string.
    '''
    # Validate origin
    origin = request.headers.get('Origin')
    if not is_valid_origin(origin):
        return jsonify({"error": "Invalid origin"}), 403

    try:
        # Get parameters from the request (use request.form for POST requests)
        key = request.form.get('key')
        object_data = request.form.get('object')  # Assuming object is passed as a string

        # Validate input (example: check if key is a string and object_data is not empty)
        if not isinstance(key, str) or not object_data:
            return jsonify({"error": "Invalid input"}), 400

        # **IMPORTANT SECURITY CONSIDERATION:**
        #  -  Directly evaluating or executing code from user input is extremely dangerous.
        #  -  The following code is a placeholder and MUST be replaced with a SAFE and SECURE method
        #     to access the value from the object.  Consider using a predefined mapping of keys to
        #     attributes or a safe data access method.  NEVER use eval() or exec() with user-provided data.

        # **UNSAFE EXAMPLE (DO NOT USE IN PRODUCTION):**
        # value = eval(f"object_data.{key}")

        # **SAFE EXAMPLE (REPLACE WITH YOUR ACTUAL LOGIC):**
        # Assuming object_data is a JSON string representing a dictionary:
        import json
        try:
            data = json.loads(object_data)
            value = data.get(key, None)  # Safely access the value using .get()
            if value is None:
                return jsonify({"error": "Key not found"}), 404
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid object format"}), 400

        return jsonify({"value": str(value)})  # Return the value as a string

    except Exception as e:
        # Log the error for debugging purposes (do not expose sensitive information in the error message)
        print(f"Error processing request: {e}")
        return jsonify({"error": "An error occurred"}), 500

# Example route to generate CSRF token
@app.route('/get_token', methods=['GET'])
def get_token():
    return jsonify({'csrf_token': generate_csrf_token()})

if __name__ == '__main__':
    # Ensure HTTPS is used in production
    # In a production environment, use a WSGI server like Gunicorn with TLS enabled.
    # Example (for development only - DO NOT USE THIS IN PRODUCTION):
    # app.run(debug=True, ssl_context='adhoc')  # Generates a self-signed certificate
    app.run(debug=True)

