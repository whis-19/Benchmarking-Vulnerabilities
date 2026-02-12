from flask import Flask, request, abort, make_response
import ast
import re
import secrets
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a strong secret key

# CSRF protection using Flask-WTF (example, can be replaced with other vetted libraries)
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(16) # CSRF secret key

# Rate limiting (example using Flask-Limiter)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example rate limits
)

# Authentication decorator (example)
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not authenticate(auth.username, auth.password):
            return authenticate_response()
        return f(*args, **kwargs)
    return decorated

def authenticate(username, password):
    """Verify username and password."""
    # Replace with your actual authentication logic (e.g., database lookup)
    # This is a placeholder and should not be used in production without proper security measures.
    return username == 'admin' and password == 'password'

def authenticate_response():
    """Sends a 401 response that enables basic auth"""
    return make_response(
    'Could not verify your access!', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})


@app.route('/eval', methods=['POST'])
@csrf.exempt # Exempt from CSRF protection for demonstration purposes.  REMOVE THIS IN PRODUCTION.  Use proper CSRF handling.
@limiter.limit("5/minute") # Limit requests to prevent abuse
@require_auth # Require authentication
def contents_dict():
    '''
    Get the data from the request using 'file_contents'.
    Remove anything before the first '{' and after the last '}'.
    Return the content by evaluating it to a dictionary.
    '''
    if request.method == 'POST':
        file_contents = request.form.get('file_contents', '')

        # Input validation and sanitization
        if not isinstance(file_contents, str):
            return "Invalid input: file_contents must be a string", 400

        # Extract the dictionary-like part
        try:
            start_index = file_contents.index('{')
            end_index = file_contents.rindex('}') + 1
            dict_string = file_contents[start_index:end_index]
        except ValueError:
            return "Invalid input: Could not find valid dictionary format", 400

        # Safely evaluate the string to a dictionary using ast.literal_eval
        try:
            data = ast.literal_eval(dict_string)
            if not isinstance(data, dict):
                return "Invalid input: Input must evaluate to a dictionary", 400
            return data, 200
        except (ValueError, SyntaxError):
            return "Invalid input: Could not safely evaluate to a dictionary", 400
    else:
        abort(405)  # Method Not Allowed


if __name__ == '__main__':
    # Never run in production with debug=True
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

