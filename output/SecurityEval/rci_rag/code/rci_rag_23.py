from flask import Flask, request, session, render_template_string, abort, g, make_response
import secrets
import re
from markupsafe import escape
import logging
import os
import uuid  # For generating nonces

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# Configure session cookie for enhanced security
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF (Lax is a good default)
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Security:  Content Security Policy (CSP) to mitigate XSS
@app.after_request
def add_security_headers(response):
    nonce = uuid.uuid4().hex
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none'; img-src 'self' data:; style-src 'self' 'nonce-{nonce}'; font-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=()'
    response.headers['Feature-Policy'] = 'geolocation \'none\''
    g.csp_nonce = nonce
    return response


@app.route('/', methods=['GET', 'POST'])
def index():
    '''
    Get the module version from the request object, but in a SAFE way.
    '''
    if request.method == 'POST':
        module_name = request.form.get('module_name')

        # Input Validation:  Strict allowlist for module_name
        if not re.match(r"^[a-zA-Z0-9_]+$", module_name):
            logging.warning(f"Invalid module name submitted: {module_name}")
            return "Invalid module name.  Only alphanumeric characters and underscores allowed.", 400

        #  Safe import and version retrieval (using a whitelist)
        allowed_modules = ['urllib', 'json', 'datetime', 'math'] # Example whitelist - be VERY restrictive
        # Rationale: urllib - needed for network requests, json - for handling JSON data, datetime - for date/time operations, math - for mathematical calculations.
        try:
            if module_name in allowed_modules:
                module = __import__(module_name)
                version = getattr(module, '__version__', 'Version not available')
                result = f"The version of {escape(module_name)} is: {escape(version)}" # Escape output
                logging.info(f"Successfully retrieved version for module: {module_name}")
            else:
                logging.warning(f"Attempted access to disallowed module: {module_name}")
                result = "Module not allowed."
        except ImportError as e:
            logging.error(f"Module not found: {module_name} - {e}")
            result = "Module not found."
        except Exception as e:
            logging.exception(f"An error occurred while processing module {module_name}: {e}") # Log the full exception
            result = "An error occurred. See logs for details." # Don't expose sensitive info to the user

        return render_template_string('''
            <h1>Module Version</h1>
            <p>{{ result }}</p>
            <a href="/">Back</a>
        ''', result=result)

    # CSRF protection using Double Submit Cookie
    session['csrf_token'] = secrets.token_hex(16)
    csrf_token = session['csrf_token']
    nonce = getattr(g, 'csp_nonce', '')

    resp = make_response(render_template_string('''
        <h1>Get Module Version</h1>
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            Module Name: <input type="text" name="module_name"><br><br>
            <input type="submit" value="Get Version">
        </form>
        <style nonce="{{ nonce }}">
            body { font-family: sans-serif; }
        </style>
    ''', csrf_token=csrf_token, nonce=nonce))
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Lax')
    return resp


# CSRF validation
@app.before_request
def validate_csrf_token():
    if request.method == 'POST':
        csrf_token_form = request.form.get('csrf_token')
        csrf_token_cookie = request.cookies.get('csrf_token')
        csrf_token_session = session.get('csrf_token')

        if not csrf_token_form or not csrf_token_cookie or not csrf_token_session or \
           csrf_token_form != csrf_token_cookie or csrf_token_form != csrf_token_session:
            logging.warning("CSRF token validation failed.")
            abort(400, 'CSRF token is missing or invalid.')


@app.errorhandler(400)
def bad_request(e):
    logging.warning(f"Bad Request: {e}")
    return "Bad Request: " + str(e), 400


if __name__ == '__main__':
    # Consider using a WSGI server like gunicorn or uWSGI in production
    # Example: gunicorn --bind 0.0.0.0:5000 your_app:app
    # Ensure dependencies are managed using requirements.txt (pip freeze > requirements.txt)
    app.run(debug=False, host='0.0.0.0', port=5000)

