from flask import Flask, request, jsonify, make_response
import json
import os
import secrets
from urllib.parse import urlparse

app = Flask(__name__)
# Generate a secret key for the app
app.secret_key = secrets.token_hex(32)

# CSP Header - Adjust as needed for your specific requirements
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-{nonce}'; "  # Use nonce for inline scripts
    "style-src 'self' 'unsafe-inline'; "  # Consider using hashes or nonces for styles too
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self';" # Only allow connections to the same origin
)

# Allowed Domains/IPs (Example - customize this)
ALLOWED_DOMAINS = ["example.com", "127.0.0.1"]  # Add your allowed domains/IPs

def is_valid_domain(url):
    """
    Validates if the domain of the URL is in the allowlist.
    """
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc in ALLOWED_DOMAINS
    except:
        return False

def generate_nonce():
    """Generates a cryptographically secure nonce."""
    return secrets.token_urlsafe(16)

def validate_payload(payload):
    """
    Validates and sanitizes the payload.  This is a crucial security step.
    Implement more robust validation based on your expected data structure.
    """
    if not isinstance(payload, dict):
        return False, "Payload must be a dictionary"

    if "name" not in payload:
        return False, "Payload must contain a 'name' key"

    # Example sanitization:  Limit the length of the name
    if not isinstance(payload["name"], str) or len(payload["name"]) > 100:
        return False, "'name' must be a string and less than 100 characters"

    # Further sanitization examples:
    # - Check for allowed characters (e.g., alphanumeric only)
    # - Convert to lowercase/uppercase
    # - Strip whitespace

    return True, None  # Payload is valid

@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    nonce = generate_nonce()
    csp = CSP_POLICY.format(nonce=nonce)
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin' # Or 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=()' # Disable geolocation, customize as needed
    return response

@app.route('/api', methods=['GET'])
def api_endpoint():
    """
    API endpoint that retrieves the 'name' value from a JSON payload
    passed as a URL parameter.
    """
    # 1. Get the payload from the URL parameter
    payload_str = request.args.get('payload')

    if not payload_str:
        return jsonify({"error": "Payload parameter is missing"}), 400

    # 2. Load the payload into a dictionary
    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON payload"}), 400

    # 3. Validate and sanitize the payload
    is_valid, error_message = validate_payload(payload)
    if not is_valid:
        return jsonify({"error": error_message}), 400

    # 4. Extract the 'name' value (after validation)
    name = payload['name']

    # 5. Escape the output before rendering (very important!)
    #    In this case, we're returning JSON, so Flask automatically escapes it.
    #    If you were rendering HTML, you'd need to use a templating engine
    #    like Jinja2 with autoescape enabled, or manually escape the output.

    return jsonify({"name": name})

# Example of a route that requires CSRF protection (using a library like Flask-WTF)
# This example is incomplete and requires Flask-WTF to be installed and configured.
# from flask_wtf import FlaskForm
# from wtforms import StringField, SubmitField
# from wtforms.validators import DataRequired
# from flask_wtf.csrf import CSRFProtect, generate_csrf

# class MyForm(FlaskForm):
#     name = StringField('Name', validators=[DataRequired()])
#     submit = SubmitField('Submit')

# csrf = CSRFProtect(app)

# @app.route('/form', methods=['GET', 'POST'])
# def my_form():
#     form = MyForm()
#     if form.validate_on_submit():
#         # Process the form data (after CSRF validation)
#         name = form.name.data
#         return f"Hello, {name}!"
#     return render_template('form.html', form=form, csrf_token=generate_csrf())

# Example of URL validation before redirecting (if needed)
@app.route('/redirect')
def redirect_route():
    target_url = request.args.get('url')

    if not target_url:
        return "Missing URL parameter", 400

    if is_valid_domain(target_url):
        #  NEVER use redirect(target_url) directly without validation!
        return f"Redirecting to {target_url} (This is just a placeholder - implement the actual redirect safely)" # Replace with a safe redirect
    else:
        return "Invalid URL", 400

if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server like Gunicorn or uWSGI.
    #  Also, make sure to use HTTPS in production.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

