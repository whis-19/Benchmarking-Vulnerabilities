from flask import request, redirect, Flask, session
from urllib.parse import urlparse
import secrets
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key

ALLOWED_SCHEMES = ['http', 'https']
ALLOWED_HOSTS = ['example.com', 'www.example.com']  # Add your allowed hosts here

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.route('/flask_redirect', methods=['GET', 'POST'])
def flask_redirect():
    """
    Get the url from the request and redirect to it, but only after validation.
    """
    if request.method == 'POST':
        target = request.form.get('url')

        if not target:
            return "Error: No URL provided.", 400

        try:
            parsed_url = urlparse(target)
        except:
            return "Error: Invalid URL format.", 400

        if not parsed_url.scheme or not parsed_url.netloc:
            return "Error: Incomplete URL.", 400

        if parsed_url.scheme not in ALLOWED_SCHEMES:
            return "Error: Disallowed scheme.", 400

        # Handle arbitrary subdomain sequences correctly
        host = parsed_url.netloc
        if host not in ALLOWED_HOSTS:
            return "Error: Disallowed host.", 400

        # CSRF protection
        if 'csrf_token' not in session or session['csrf_token'] != request.form.get('csrf_token'):
            return "Error: CSRF token is missing or invalid.", 400

        return redirect(target, code=302)  # Use 302 for temporary redirect

    # Generate CSRF token for GET requests
    session['csrf_token'] = secrets.token_hex(16)
    return f"""
    <form method="post">
        URL: <input type="text" name="url">
        <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
        <input type="submit" value="Go">
    </form>
    """

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

