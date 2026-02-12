import re
import secrets
import urllib.parse
from flask import Flask, request, redirect, make_response, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a cryptographically strong secret key

# Regular expression to match URLs containing example.com
ALLOWED_HOST = r"^(example\.com)$"

@app.before_request
def before_request():
    """Set the Content-Type header to include charset."""
    if request.endpoint != 'static':
        request.charset = 'utf-8'

@app.route('/')
def index():
    """Default route."""
    return "Welcome!  Use /redirect?target=<url> to redirect."

@app.route('/redirect')
def redirect_route():
    """Redirect route with validation."""
    target = request.args.get('target')

    if not target:
        return "Target parameter is missing.", 400  # Bad Request

    try:
        parsed_url = urllib.parse.urlparse(target)
    except:
        return "Invalid URL format.", 400

    if not parsed_url.netloc:
        return "Invalid URL: Missing network location (e.g., example.com).", 400

    if re.match(ALLOWED_HOST, parsed_url.netloc):
        response = make_response(redirect(target))
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response
    else:
        response = make_response(redirect("/"))
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

@app.after_request
def after_request(response):
    """Set security headers."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

