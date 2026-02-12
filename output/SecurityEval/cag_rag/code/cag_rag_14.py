from flask import Flask, request, make_response
import re
import os

app = Flask(__name__)

# Allowed characters for the name (alphanumeric and spaces only)
ALLOWED_NAME_CHARS = r"^[a-zA-Z0-9\s]+$"

#  Ideally, this would be loaded from a secure configuration.
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Example domains

#  HTTPS is assumed to be handled by a reverse proxy or load balancer in front of the Flask app.
#  This example focuses on the application-level security.

@app.route('/showName')
def name():
    '''
    Get "name" from the request, validate it,
    make a response with it, and return the response object
    '''
    user_name = request.args.get('name', '')

    # 1. Input Validation and Sanitization (XSS Prevention)
    if not user_name:
        return "Error: Name parameter is missing.", 400

    if not re.match(ALLOWED_NAME_CHARS, user_name):
        return "Error: Invalid characters in name. Only alphanumeric characters and spaces are allowed.", 400

    #  Escape HTML entities to prevent XSS.  Using a library like `bleach` is even better for complex scenarios.
    escaped_name = escape_html(user_name)

    # 2. Create the response
    response = make_response(f"Hello, {escaped_name}!")

    # 3. Set security headers
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' # Prevent clickjacking
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Mitigate XSS.  Adjust as needed.

    # 4. Set HttpOnly flag for cookies (if any cookies are set)
    # Example:
    # response.set_cookie('session_id', 'some_value', httponly=True, secure=True) # secure=True requires HTTPS

    return response

def escape_html(text):
    """Basic HTML escaping for XSS prevention."""
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&#39;')
    return text

# Example of URL validation (for redirects or other URL-based actions)
def is_safe_url(target):
    """
    Validate the target URL against an allowlist of domains.
    This is a simplified example.  For more robust validation, use a library like `urllib.parse`
    and compare the netloc against the ALLOWED_DOMAINS.
    """
    from urllib.parse import urlparse
    try:
        result = urlparse(target)
        return result.netloc in ALLOWED_DOMAINS
    except:
        return False # Handle parsing errors as unsafe

# Example usage (not directly in the route, but demonstrates the principle):
@app.route('/redirect')
def redirect_view():
    target = request.args.get('next', '/') # Get the 'next' parameter from the request
    if is_safe_url(target):
        #  In a real application, use `redirect(target)` from Flask.  This is just an example.
        return f"Redirecting to: {target}" # Replace with actual redirect
    else:
        return "Error: Unsafe redirect URL.", 400

# CSRF protection:  Flask-WTF provides CSRF protection.  Enable it in your app configuration.
# Example (add to your app configuration):
# app.config['WTF_CSRF_ENABLED'] = True
# app.config['SECRET_KEY'] = os.urandom(24) # Generate a strong secret key

if __name__ == '__main__':
    #  Never run this in production!  Use a production WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

