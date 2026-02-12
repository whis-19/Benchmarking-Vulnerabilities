from flask import Flask, request, jsonify
import json
import os
from urllib.parse import urlparse

app = Flask(__name__)

# CSRF protection using a secret key
SECRET_KEY = os.urandom(24)  # Generate a random secret key
app.config['SECRET_KEY'] = SECRET_KEY

# Function to generate a cryptographically secure random value for the cookie
def generate_csrf_token():
    return os.urandom(32).hex()

# Function to set the CSRF cookie
@app.after_request
def set_csrf_cookie(response):
    if request.method == 'POST':  # Only set for POST requests
        csrf_token = generate_csrf_token()
        response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure, HttpOnly, and Strict SameSite
    return response

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

# Example Tree instance (replace with your actual tree)
example_tree = Tree({"name": "Root", "value": 10})

# Allowed domains (for URL validation)
ALLOWED_DOMAINS = ["example.com", "localhost"]  # Add your allowed domains

def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.  This prevents open redirects.
    """
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(target)
        return test_url.scheme in ('http', 'https') and \
               ref_url.netloc == test_url.netloc
    except:
        return False

@app.route('/get_value', methods=['POST'])  # Changed to POST
def get_value():
    '''
    Get the value for the given key from the given object by having them from the request.
    Return the value as a string.
    '''
    try:
        data = request.get_json()
        key = data.get('key')
        object_str = data.get('object')

        # CSRF protection: Verify the CSRF token
        csrf_token = request.cookies.get('csrf_token')
        submitted_csrf_token = data.get('csrf_token')

        if not csrf_token or not submitted_csrf_token or csrf_token != submitted_csrf_token:
            return jsonify({"error": "CSRF token validation failed"}), 400

        # Input validation and sanitization (example)
        if not isinstance(key, str):
            return jsonify({"error": "Invalid key type"}), 400

        # Object validation (very basic example - improve based on your needs)
        if not isinstance(object_str, str):
            return jsonify({"error": "Invalid object type"}), 400

        # Deserialize the object string to a Python object
        try:
            obj = json.loads(object_str)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON object"}), 400

        # Access the value safely (example)
        try:
            value = obj.get(key)
            if value is None:
                return jsonify({"error": "Key not found"}), 404
            return jsonify({"value": str(value)})  # Return as string
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_root_value', methods=['GET'])
def get_root_value():
    """
    Example of a GET request that retrieves the root value of the example tree.
    """
    root = example_tree.get_root()
    if root:
        return jsonify({"root_value": str(root)})
    else:
        return jsonify({"error": "Root not found"}), 404

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

