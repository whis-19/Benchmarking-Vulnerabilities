from flask import Flask, redirect, request, session
import re
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = 'YOUR_SECRET_KEY'  # Replace with a strong, randomly generated key

# Set HttpOnly flag for session cookie
@app.after_request
def add_security_headers(resp):
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.set_cookie('session', session.get('session', ''), httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes
    return resp


ALLOWED_HOSTS = ['example.com', 'www.example.com']  # Add your allowed hosts here

def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.

    This function parses the URL and validates it against a list of allowed hosts.
    It also prevents common redirection vulnerabilities.
    """
    try:
        parsed_url = urlparse(target)
        # Check if scheme is present and is either http or https
        if not parsed_url.scheme or parsed_url.scheme not in ['http', 'https']:
            return False

        # Check if netloc (hostname) is present
        if not parsed_url.netloc:
            return False

        # Check if the hostname is in the allowed list
        if parsed_url.netloc not in ALLOWED_HOSTS:
            return False

        # Prevent javascript: or data: URLs
        if parsed_url.scheme.lower() in ['javascript', 'data']:
            return False

        return True
    except:
        return False  # Handle parsing errors as unsafe


@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request,
    use a regular expression to check if it is a valid target,
    then redirect to the target URL
    '''
    target = request.args.get('target')

    if not target:
        return "Error: No target URL provided.", 400

    if is_safe_url(target):
        return redirect(target)
    else:
        return "Error: Unsafe redirect target.", 400


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

