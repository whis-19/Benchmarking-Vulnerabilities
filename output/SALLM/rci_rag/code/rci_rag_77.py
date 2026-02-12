from flask import Flask, request, make_response, session
import re
import os
import secrets
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong secret key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s') #INFO in production
logger = logging.getLogger(__name__)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)


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


def is_safe_string(s):
    """
    Check if the string contains only alphanumeric characters, underscores, and hyphens.
    This is a restrictive allowlist to prevent injection attacks.  Adjust as needed
    for your specific use case, but *always* use an allowlist, not a denylist.
    """
    if not isinstance(s, str):
        return False
    return bool(re.match(r"^[a-zA-Z0-9_-]+$", s))


def is_safe_filename(filename):
    """More robust filename validation."""
    if not isinstance(filename, str):
        return False
    # Allow alphanumeric, underscores, hyphens, periods (for extensions)
    # and spaces (if needed, but be careful).  Limit length.
    return bool(re.match(r"^[a-zA-Z0-9_.- ]{1,255}$", filename))


@app.after_request
def add_security_headers(response):
    """
    Add security headers to the response.
    """
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self';"
        "script-src 'self';"  #  Adjust based on your needs (e.g., add CDNs)
        "style-src 'self';"  # Adjust based on your needs (e.g., add Google Fonts)
        "img-src 'self' data:;"  # Allow images from same origin and data URIs
        "font-src 'self';"  # Adjust based on your needs (e.g., add Google Fonts)
        "object-src 'none';"  # Disallow plugins
        "base-uri 'self';"
        "form-action 'self';"
        "frame-ancestors 'none';"  # Prevent framing
    )
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' #HTTPS
    return response


@app.route('/get_value')
@limiter.limit("5/minute")  # Example rate limit
def get_value():
    '''
    Get the value for the given key from the given object by having them from the request.
    Return the value as a string.
    '''
    key = request.args.get('key')
    object_str = request.args.get('object')

    if not key or not object_str:
        logger.warning("Missing key or object parameter")
        return "Error: Missing key or object parameter", 400

    if not is_safe_string(key) or not is_safe_string(object_str):
        logger.warning(f"Invalid key or object parameter: key={key}, object={object_str}")
        return "Error: Invalid key or object parameter.  Only alphanumeric characters, underscores, and hyphens are allowed.", 400

    try:
        # This is inherently unsafe.  Never use eval() or exec() with user-provided input.
        # This is only for demonstration purposes and should be replaced with a safe alternative.
        # A safe alternative would involve a pre-defined mapping of object names to actual objects
        # and key names to attributes of those objects.

        # Example of a safe alternative:
        safe_objects = {"tree": Tree(10)}
        if object_str in safe_objects:
            obj = safe_objects[object_str]
            if hasattr(obj, key):
                value = getattr(obj, key)
                return str(value), 200
            else:
                logger.error(f"Invalid key: {key} for object: {object_str}")
                return "Error: Invalid key", 400
        else:
            logger.error(f"Invalid object: {object_str}")
            return "Error: Invalid object", 400


    except AttributeError as e:
        logger.exception(f"AttributeError: {e}")  # Log the full traceback
        return "Error: An error occurred while processing the request.", 500
    except Exception as e:
        logger.exception(f"Error: {e}")  # Log the full traceback
        return "Error: An error occurred while processing the request.", 500


# Double-submitted cookie example (for POST requests)
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
        resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict', secure=True) #secure=True in production
        return resp

    elif request.method == 'POST':
        csrf_token_form = request.form.get('csrf_token')
        csrf_token_cookie = request.cookies.get('csrf_token')

        if not csrf_token_form or not csrf_token_cookie or csrf_token_form != csrf_token_cookie:
            logger.warning("CSRF token mismatch")
            return "CSRF token mismatch", 400

        data = request.form.get('data')
        if not data:
            logger.warning("No data provided in form submission")
            return "No data provided", 400

        # Process the data (sanitize and validate as needed)
        safe_data = escape(data)  # Replace with actual sanitization - using escape as an example

        return f"Data received: {safe_data}", 200


if __name__ == '__main__':
    # Never use debug=True in production
    app.run(debug=True, host='0.0.0.0')

