import os
import html
from typing import Dict, Any
from urllib.parse import urlparse

from flask import Flask, request, Response, render_template, session, redirect, url_for
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong secret key
csrf = CSRFProtect(app)

# Template directory (ensure it exists)
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app.template_folder = TEMPLATE_DIR

# Allowed characters for the 'name' parameter.  Restrict to alphanumeric and spaces.
ALLOWED_NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

# Allowed domains/IPs (example - adjust to your needs)
ALLOWED_DOMAINS = ["example.com", "127.0.0.1", "localhost"]  # Add your allowed domains

# Function to validate URLs (basic example - enhance as needed)
def is_valid_url(url: str) -> bool:
    """
    Validates a URL against an allowlist of domains.
    """
    try:
        result = urlparse(url)
        if result.scheme not in ("http", "https"):
            return False
        if result.netloc not in ALLOWED_DOMAINS:
            return False
        return True
    except:
        return False

def sanitize_name(name: str) -> str:
    """
    Sanitizes the 'name' parameter by removing invalid characters and escaping HTML.
    """
    sanitized_name = "".join(c for c in name if c in ALLOWED_NAME_CHARS)
    return html.escape(sanitized_name)  # Escape HTML to prevent XSS

def render_response_from_env(env: Dict[str, Any]) -> Response:
    """
    Renders a template with a sanitized 'name' parameter from the request.
    """
    name = request.args.get("name", "")  # Get the 'name' parameter from the request

    # Sanitize the name parameter
    sanitized_name = sanitize_name(name)

    # Get the template from the environment (assuming it's passed in)
    template = env.get("template")

    if not template:
        return Response("Error: Template not found in environment.", status=500)

    try:
        rendered_template = render_template(template, name=sanitized_name)
        response = Response(rendered_template, mimetype='text/html; charset=utf-8') # Specify encoding
        response.headers['Content-Security-Policy'] = "default-src 'self'" # Add CSP header
        response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
        response.headers['X-Frame-Options'] = 'SAMEORIGIN' # Prevent clickjacking
        response.headers['X-XSS-Protection'] = '1; mode=block' # Enable XSS protection
        return response
    except Exception as e:
        return Response(f"Error rendering template: {str(e)}", status=500)


@app.route("/")
def home():
    """
    Handles the home route and calls render_response_from_env.
    """
    env = {"template": "index.html"}  # Pass the template name in the environment
    return render_response_from_env(env)

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Example route to demonstrate URL validation
@app.route("/redirect")
def redirect_url():
    target_url = request.args.get("url")
    if target_url and is_valid_url(target_url):
        return redirect(target_url)
    else:
        return "Invalid URL", 400

# Example form with CSRF protection
@app.route('/form', methods=['GET', 'POST'])
def form_example():
    if request.method == 'POST':
        # Process the form data (after CSRF validation)
        name = request.form.get('name')
        # Sanitize and process 'name' as needed
        return render_template('form_result.html', name=name)
    return render_template('form.html')

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, ssl_context='adhoc') # Use HTTPS.  'adhoc' for testing only.  Use proper certificates in production.

