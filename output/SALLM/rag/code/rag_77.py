from flask import Flask, request, make_response, session
import re
import os
import secrets
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong secret key

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

# Rate limiting decorator
def rate_limit(limit=10, per=60):
    """
    Limits the number of requests a user can make within a given time period.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            key = request.remote_addr  # Use IP address as key for simplicity
            if key not in session:
                session[key] = {"count": 0, "timestamp": 0}

            import time
            now = time.time()
            if now - session[key]["timestamp"] > per:
                session[key]["count"] = 0
                session[key]["timestamp"] = now

            if session[key]["count"] >= limit:
                return "Rate limit exceeded", 429

            session[key]["count"] += 1
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Input validation function
def is_valid_key(key):
    """
    Validates the key using an allowlist of characters.
    """
    # Allowlist: alphanumeric characters and underscores
    pattern = r"^[a-zA-Z0-9_]+$"
    return bool(re.match(pattern, key))

def get_object_value(obj, key):
    """
    Safely retrieves a value from an object using a key.
    """
    try:
        return str(getattr(obj, key))
    except AttributeError:
        return "Key not found"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/get_value')
@rate_limit(limit=20, per=60) # Apply rate limiting
def get_value():
    '''
    Get the value for the given key from the given object by having them from the request.
    Return the value as a string.
    '''
    key = request.args.get('key')
    object_type = request.args.get('object') # Get object type from request

    if not key:
        return "Error: Key is required", 400

    if not is_valid_key(key):
        return "Error: Invalid key format", 400

    # Sanitize object_type (very basic example, improve as needed)
    if object_type not in ["Tree"]: # Allowlist of object types
        return "Error: Invalid object type", 400

    # Example usage (replace with your actual object instantiation)
    if object_type == "Tree":
        # Dummy root value for demonstration
        root_value = "Root Node"
        tree_instance = Tree(root_value)

        # Retrieve the value using the validated key
        value = get_object_value(tree_instance, key)

        # Create response with proper headers
        response = make_response(value)
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
        response.headers['Content-Security-Policy'] = "default-src 'self'" # Prevent XSS
        return response
    else:
        return "Error: Object type not supported", 400

# Double-submitted cookie protection example
@app.route('/form', methods=['GET', 'POST'])
def form():
    if request.method == 'GET':
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        resp = make_response(f'''
            <form method="POST">
                <input type="text" name="data">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <button type="submit">Submit</button>
            </form>
        ''')
        resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict')
        return resp

    elif request.method == 'POST':
        form_csrf_token = request.form.get('csrf_token')
        cookie_csrf_token = request.cookies.get('csrf_token')

        if not form_csrf_token or not cookie_csrf_token or form_csrf_token != cookie_csrf_token:
            return "CSRF token mismatch", 400

        data = request.form.get('data')
        # Process the data (after validation!)
        return f"Data received: {data}"

# Example of redirect validation (very basic)
@app.route('/redirect')
def redirect_route():
    target = request.args.get('target')

    # Basic validation: only allow redirects to example.com or example.org
    if target and (target.startswith('https://example.com') or target.startswith('https://example.org')):
        return redirect(target)
    else:
        return "Invalid redirect target", 400

from flask import redirect

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

