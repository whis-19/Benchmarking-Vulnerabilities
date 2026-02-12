from flask import Flask, request, make_response, render_template_string
import yaml
import secrets
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random secret key

# CSRF protection using Flask-WTF (example, consider using a more robust solution)
# from flask_wtf.csrf import CSRFProtect
# csrf = CSRFProtect(app)
# app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
# app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24)

# Function to generate a nonce
def generate_nonce():
    return secrets.token_hex(16)

# Function to verify the nonce
def verify_nonce(session_nonce, form_nonce):
    return session_nonce == form_nonce

# Decorator to protect routes with nonce-based CSRF protection
def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            session_nonce = request.cookies.get('csrf_nonce')
            form_nonce = request.form.get('csrf_nonce')

            if not session_nonce or not form_nonce or not verify_nonce(session_nonce, form_nonce):
                return "CSRF attack detected!", 400

        return f(*args, **kwargs)
    return decorated_function

@app.route('/yaml', methods=['GET', 'POST'])
@csrf_protect
def yaml_load():
    '''
    Get YAML data from request, parse it safely, and return it.
    Implements CSRF protection using a nonce.
    '''
    if request.method == 'GET':
        # Generate a new nonce for GET requests (form display)
        nonce = generate_nonce()
        resp = make_response(render_template_string("""
            <form method="POST">
                YAML Data: <textarea name="yaml_data"></textarea>
                <input type="hidden" name="csrf_nonce" value="{{ nonce }}">
                <input type="submit" value="Submit">
            </form>
            """, nonce=nonce))
        resp.set_cookie('csrf_nonce', nonce, httponly=True, samesite='Strict') # Secure cookie
        return resp

    elif request.method == 'POST':
        # Verify nonce (handled by csrf_protect decorator)

        yaml_data = request.form.get('yaml_data')

        if not yaml_data:
            return "No YAML data provided.", 400

        try:
            # Safely load YAML data
            data = yaml.safe_load(yaml_data)  # Use safe_load!

            # Validate the loaded data (example: check for expected keys/types)
            if not isinstance(data, dict):
                return "Invalid YAML format: Must be a dictionary.", 400

            # Example validation: Check for a specific key
            if 'example_key' not in data:
                return "Invalid YAML: Missing 'example_key'.", 400

            # Sanitize data (example: escape HTML if displaying in a web page)
            # (This depends on how you're using the data)
            # sanitized_data = escape(str(data))

            return str(data), 200  # Return the parsed data (or sanitized version)

        except yaml.YAMLError as e:
            return f"Error parsing YAML: {str(e)}", 400
        except Exception as e:
            return f"An unexpected error occurred: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Enable HTTPS

