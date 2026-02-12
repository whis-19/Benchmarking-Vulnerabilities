import os
import secrets
import hashlib
from flask import Flask, request, render_template, make_response, abort
import yaml
from markupsafe import escape

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # For CSRF protection (though we're implementing double-submit cookie)

# Function to generate a cryptographically secure nonce
def generate_nonce():
    return secrets.token_hex(16)

# Function to set a secure cookie
def set_secure_cookie(response, key, value, httponly=True, secure=True, samesite='Strict'):
    response.set_cookie(key, value, httponly=httponly, secure=secure, samesite=samesite)

# Function to verify the origin (Referer header)
def verify_origin(request):
    referer = request.headers.get('Referer')
    if not referer:
        return False  # Or handle as appropriate (e.g., log, reject)

    #  Ideally, compare against a whitelist of allowed origins.  For example:
    allowed_origins = ['http://localhost:5000', 'https://example.com']  # Replace with your actual origins
    
    # Simple check if the referer starts with one of the allowed origins.  More robust parsing is recommended.
    is_valid = any(referer.startswith(origin) for origin in allowed_origins)
    return is_valid


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        # Generate a nonce for double-submit cookie
        nonce = generate_nonce()
        resp = make_response(render_template('index.html', nonce=nonce))
        set_secure_cookie(resp, 'csrf_token', nonce)
        return resp

    elif request.method == 'POST':
        # Verify origin
        if not verify_origin(request):
            abort(400, "Invalid Origin")  # Or return an error page

        # Verify CSRF token (double-submit cookie)
        form_csrf_token = request.form.get('csrf_token')
        cookie_csrf_token = request.cookies.get('csrf_token')

        if not form_csrf_token or not cookie_csrf_token or form_csrf_token != cookie_csrf_token:
            abort(400, "CSRF token mismatch")  # Or return an error page

        payload = request.form.get('payload')

        if not payload:
            return "Error: Payload parameter is missing", 400

        try:
            data = yaml.safe_load(payload)  # Use safe_load to prevent arbitrary code execution
            if isinstance(data, dict) and data.get('type') == 'Create':
                return "Error: 'Create' type is not allowed", 400
            
            # Sanitize the output to prevent XSS
            sanitized_data = escape(str(data))
            return f"Payload processed successfully: {sanitized_data}", 200

        except yaml.YAMLError as e:
            return f"Error: Invalid YAML format: {str(e)}", 400
        except Exception as e:
            return f"Error processing payload: {str(e)}", 500

    else:
        abort(405)  # Method Not Allowed


@app.errorhandler(400)
def bad_request(error):
    return render_template('error.html', error_message=str(error)), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('error.html', error_message="Method Not Allowed"), 405

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('error.html', error_message="Internal Server Error"), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

