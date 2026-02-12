from flask import Flask, request, make_response, render_template_string, abort
import yaml
import secrets
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key

# Set HttpOnly on session cookies (if using sessions)
@app.after_request
def add_security_headers(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


def generate_csrf_token():
    return secrets.token_hex(16)

def validate_csrf(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        csrf_token_form = request.form.get('csrf_token')
        csrf_token_cookie = request.cookies.get('csrf_token')

        if not csrf_token_form or not csrf_token_cookie or csrf_token_form != csrf_token_cookie:
            abort(400, description="CSRF token mismatch")  # Or return an error page
        return f(*args, **kwargs)
    return decorated_function


@app.route('/yaml', methods=['GET', 'POST'])
def yaml_load():
    """
    Get YAML data from request, parse it safely, and return it.
    Implements CSRF protection.
    """
    if request.method == 'GET':
        csrf_token = generate_csrf_token()
        resp = make_response(render_template_string('''
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <textarea name="yaml_data" rows="10" cols="50"></textarea>
                <button type="submit">Parse YAML</button>
            </form>
            ''', csrf_token=csrf_token))
        resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict') # Secure and Strict for production
        return resp

    elif request.method == 'POST':
        # CSRF Validation
        csrf_token_form = request.form.get('csrf_token')
        csrf_token_cookie = request.cookies.get('csrf_token')

        if not csrf_token_form or not csrf_token_cookie or csrf_token_form != csrf_token_cookie:
            abort(400, description="CSRF token mismatch")  # Or return an error page

        yaml_data = request.form.get('yaml_data')

        if not yaml_data:
            return "No YAML data provided.", 400

        try:
            # Use yaml.safe_load to prevent arbitrary code execution
            data = yaml.safe_load(yaml_data)
            return str(data)  # Or render it in a template safely
        except yaml.YAMLError as e:
            return f"Error parsing YAML: {str(e)}", 400
        except Exception as e:
            return f"An unexpected error occurred: {str(e)}", 500

    else:
        return "Method not allowed", 405


@app.errorhandler(400)
def bad_request(e):
    return f"Bad Request: {e.description}", 400

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)

