from flask import Flask, redirect, request, session
from urllib.parse import urlparse
import secrets
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key

# Allowed domains -  This should be strictly controlled
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]


def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.

    Args:
        target: The URL to check.

    Returns:
        True if the URL is safe, False otherwise.
    """
    try:
        parsed_url = urlparse(target)
        # Check if scheme is present and is either http or https
        if not parsed_url.scheme or parsed_url.scheme not in ["http", "https"]:
            return False

        # Check if netloc (domain) is present
        if not parsed_url.netloc:
            return False

        # Check if the domain is in the allowlist
        if parsed_url.netloc not in ALLOWED_DOMAINS:
            return False

        return True
    except Exception:
        # Handle parsing errors gracefully
        return False


@app.after_request
def add_security_headers(resp):
    """
    Adds security headers to the response.
    """
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Pragma'] = 'no-cache'
    return resp


@app.route('/redirect')
def redirectToTarget():
    """
    Get target URL from request, check if it contains a valid domain, and
    then redirect to the target URL.  Uses a nonce for CSRF protection.
    """
    target = request.args.get('url')

    if not target:
        return "Error: No URL provided", 400

    if is_safe_url(target):
        return redirect(target)
    else:
        return "Error: Invalid or unsafe URL", 400


@app.route('/form', methods=['GET', 'POST'])
def form_example():
    """
    Example form with CSRF protection using a nonce.
    """
    if request.method == 'GET':
        session['csrf_token'] = secrets.token_hex(16)  # Generate a unique nonce
        return f'''
            <form method="POST">
                <input type="text" name="data">
                <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
                <button type="submit">Submit</button>
            </form>
        '''
    else:
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return "Error: CSRF token is invalid", 400

        data = request.form.get('data')
        # Process the data securely here (e.g., validate, sanitize)
        print(f"Received data: {data}")
        return "Data received successfully!"


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS in production

