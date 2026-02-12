from flask import Flask, request, render_template, session, redirect, url_for
import secrets
import os
import re
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong secret key

ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Example allowlist
ALLOWED_COMMANDS = ["version", "help"] # Example allowlist for commands

def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  This prevents open redirects.
    """
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(target)
        return test_url.scheme in ('http', 'https') and \
               ref_url.netloc == test_url.netloc
    except:
        return False

def generate_nonce():
    """Generates a cryptographically strong nonce."""
    return secrets.token_hex(16)

@app.before_request
def before_request():
    """Sets up CSRF protection using double-submit cookie method."""
    if request.method == 'POST':
        csrf_token = request.cookies.get('csrf_token')
        form_csrf_token = request.form.get('csrf_token')

        if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
            # Log the CSRF failure for auditing
            print("CSRF validation failed!")
            # Abort the request (or handle it appropriately, e.g., redirect to an error page)
            #abort(400) # Or redirect
            return "CSRF validation failed", 400

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Handles the main page, including CSRF protection and safe module version retrieval.
    """
    if request.method == 'GET':
        nonce = generate_nonce()
        session['csrf_token'] = nonce
        resp = render_template('index.html', csrf_token=nonce)
        resp.set_cookie('csrf_token', nonce, httponly=True, samesite='Lax') # Secure in production
        return resp

    elif request.method == 'POST':
        # CSRF is handled in before_request

        module_name = request.form.get('module_name')
        command = request.form.get('command')

        if not module_name or not command:
            return "Module name and command are required.", 400

        # Validate command against allowlist
        if command not in ALLOWED_COMMANDS:
            return "Invalid command.", 400

        # Sanitize module name (very basic example, improve as needed)
        if not re.match(r"^[a-zA-Z0-9_]+$", module_name):
            return "Invalid module name.", 400

        try:
            # Instead of exec, use a safe alternative.  This example uses a dictionary
            # to map commands to functions.  This is much safer than arbitrary code execution.

            if command == "version":
                # Simulate getting a version (replace with actual safe logic)
                version = "1.2.3" # Example version
                result = f"Version of {module_name}: {version}"
            elif command == "help":
                result = "Help information for the module." # Example help
            else:
                result = "Unknown command."

            return render_template('result.html', result=result)

        except Exception as e:
            print(f"Error: {e}")
            return "An error occurred.", 500

@app.route('/redirect')
def redirect_url():
    """Handles redirects safely."""
    target = request.args.get('target')
    if not target:
        return "Missing target URL", 400

    if is_safe_url(target):
        return redirect(target)
    else:
        return "Unsafe redirect target", 400

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

if __name__ == '__main__':
    # Use HTTPS in production.  This requires setting up SSL certificates.
    # app.run(debug=True, ssl_context='adhoc') # For development only!
    app.run(debug=True) # Remove debug=True in production!

