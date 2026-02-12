import os
from flask import Flask, request, make_response, jsonify
import yaml
import secrets
from voluptuous import Schema, Required, All, Length, ALLOW_EXTRA  # Import for YAML validation example

app = Flask(__name__)

# Securely load the SECRET_KEY from an environment variable
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set!  This is critical for security.")
app.config['SECRET_KEY'] = SECRET_KEY


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Example CSP - Customize this!
    # The 'unsafe-inline' keyword in script-src allows inline scripts, which is a security risk.
    # Consider using nonces or hashes for inline scripts instead for better security.
    # Nonces involve generating a unique random value for each request, adding it to the CSP header,
    # and including it in the <script> tag. Hashes involve calculating the SHA hash of the inline script
    # and adding it to the CSP header.
    # See: https://owasp.org/www-project-secure-headers/#content-security-policy (for general CSP info)
    # and https://content-security-policy.com/examples/allow-inline-script/ (for specific inline script solutions)
    # and https://flask.palletsprojects.com/en/2.3.x/patterns/contentsecuritypolicy/ (for Flask specific implementation)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


# Example using Voluptuous (install with: pip install voluptuous)
# This is a basic example; more complex schemas may be needed for real-world applications.
# Cerberus is another popular schema validation library.
def validate_yaml(yaml_data):
    """Validates YAML data against a schema."""
    schema = Schema({
        Required('name'): All(str, Length(min=1, max=50)),
        Required('age'): int,
        'email': str,
    }, extra=ALLOW_EXTRA)

    try:
        data = yaml.safe_load(yaml_data)
        validated_data = schema(data)
        print("YAML data is valid:", validated_data)
        return validated_data
    except Exception as e:
        print("YAML data is invalid:", e)
        return None


@app.route('/process_yaml', methods=['POST'])
def process_yaml():
    """Processes YAML data from the request."""
    if request.content_type != 'application/yaml':
        return jsonify({'error': 'Invalid content type.  Must be application/yaml'}), 400

    yaml_data = request.data.decode('utf-8')
    validated_data = validate_yaml(yaml_data)

    if validated_data:
        # Process the validated data
        return jsonify({'message': 'YAML data processed successfully', 'data': validated_data}), 200
    else:
        return jsonify({'error': 'Invalid YAML data'}), 400


@app.before_request
def enforce_https():
    """Enforces HTTPS.  Best practice is to handle this at the web server level (e.g., Nginx, Apache).
    This is a supplementary check."""
    if not request.is_secure and app.env == 'production':  # Only enforce in production
        return "HTTPS is required", 400  # Or redirect to HTTPS

# ... rest of the code ...

