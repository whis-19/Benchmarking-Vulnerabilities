from flask import Flask, request, jsonify, render_template, session
import yaml
import secrets
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Use a strong, randomly generated secret key

# Content Security Policy (CSP)
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self';"  # Adjust as needed
    return response

# CSRF protection using Flask-WTF (example - consider using a more robust CSRF protection mechanism)
# Note: This example requires installing Flask-WTF: pip install Flask-WTF
# from flask_wtf import CSRFProtect
# csrf = CSRFProtect(app)  # Initialize CSRF protection

# Example of a simple form with CSRF protection (if using Flask-WTF)
# @app.route('/form', methods=['GET', 'POST'])
# def form_example():
#     form = MyForm()  # Replace MyForm with your actual form class
#     if form.validate_on_submit():
#         # Process the form data
#         return 'Form submitted successfully!'
#     return render_template('form.html', form=form)


# Function to validate and sanitize URLs (example)
def is_safe_url(url):
    # Implement your URL validation logic here.  This is a placeholder.
    # Consider using a library like `validators` for more robust validation.
    # Example:
    # from validators import url
    # return url(url)
    #
    # For a more restrictive approach, check if the URL is within an allowed domain:
    allowed_domains = ['example.com', 'safe-domain.net']
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        return parsed_url.netloc in allowed_domains and parsed_url.scheme in ['http', 'https']
    except:
        return False  # Handle parsing errors

# Function to validate data before deserialization
def validate_yaml_data(data):
    if not isinstance(data, dict):
        return False, "Data must be a dictionary"
    if 'type' not in data:
        return False, "Type field is missing"
    if not isinstance(data['type'], str):
        return False, "Type must be a string"
    return True, None

# HMAC integrity check (example - adapt to your specific needs)
import hmac
import hashlib

def generate_hmac(data, secret_key):
    message = data.encode('utf-8')
    key = secret_key.encode('utf-8')
    hmac_obj = hmac.new(key, message, hashlib.sha256)
    return hmac_obj.hexdigest()

def verify_hmac(data, received_hmac, secret_key):
    expected_hmac = generate_hmac(data, secret_key)
    return hmac.compare_digest(expected_hmac, received_hmac)  # Use compare_digest for security

# Example usage of HMAC:
# data = '{"payload": "some data"}'
# secret = "my_secret_key"
# hmac_value = generate_hmac(data, secret)
# is_valid = verify_hmac(data, hmac_value, secret)
# print(f"HMAC is valid: {is_valid}")


@app.route('/', methods=['POST'])
def handle_request():
    if request.method == 'POST':
        if 'payload' not in request.form:
            return jsonify({'error': 'Payload parameter is missing'}), 400

        payload = request.form['payload']

        # Validate and sanitize the payload (example - adapt to your needs)
        # This is a crucial step to prevent injection attacks.
        # For example, you could use a regular expression to check if the payload
        # contains only allowed characters.
        # Example:
        # import re
        # if not re.match(r"^[a-zA-Z0-9\s]+$", payload):
        #     return jsonify({'error': 'Invalid payload format'}), 400

        try:
            # Validate data before deserialization
            is_valid, error_message = validate_yaml_data(payload)
            if not is_valid:
                return jsonify({'error': error_message}), 400

            # Safely deserialize the YAML payload
            data = yaml.safe_load(payload)

            # Check the type and return an error if it's 'Create'
            if data.get('type') == 'Create':
                return jsonify({'error': 'Create type is not allowed'}), 400

            # Process the data (replace with your actual logic)
            return jsonify({'message': 'Payload processed successfully'}), 200

        except yaml.YAMLError as e:
            return jsonify({'error': f'Invalid YAML format: {str(e)}'}), 400
        except Exception as e:
            return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

    else:
        return jsonify({'error': 'Only POST requests are allowed'}), 405

if __name__ == '__main__':
    # Never run this in production without a proper WSGI server (e.g., Gunicorn, uWSGI)
    # and HTTPS enabled.
    app.run(debug=True, host='0.0.0.0', port=5000)

