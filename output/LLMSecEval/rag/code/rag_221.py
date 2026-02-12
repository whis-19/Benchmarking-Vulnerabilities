from flask import Flask, request, jsonify, session
import json
import secrets
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# Set HttpOnly flag for session cookie
@app.after_request
def add_security_headers(response):
    response.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.set_cookie('session', session.get('session', ''), httponly=True, secure=True, samesite='Lax') # Secure cookie

    return response


def is_valid_url(url):
    """
    Validates that the URL is safe to redirect to.  This is a basic example
    and should be expanded upon for production use.  Specifically, it checks
    that the scheme is either http or https and that the netloc is a safe domain.
    """
    try:
        result = urlparse(url)
        return all([
            result.scheme in ["http", "https"],
            result.netloc in ["example.com", "localhost:5000"]  # Add your allowed domains here
        ])
    except:
        return False


@app.route('/api', methods=['GET'])
def api():
    """
    API endpoint that retrieves the 'name' value from a JSON payload passed as a URL parameter.
    """
    payload_param = request.args.get('payload')

    if not payload_param:
        return jsonify({"error": "Payload parameter is missing"}), 400

    try:
        # Validate the payload parameter using an allowlist approach.
        # Only allow alphanumeric characters, underscores, and hyphens.
        if not all(c.isalnum() or c in ['_', '-', '=', '&', '{', '}', ':', '"', ','] for c in payload_param):
            return jsonify({"error": "Invalid characters in payload parameter"}), 400

        # Safely parse the JSON payload.  Handle potential errors.
        try:
            payload = json.loads(payload_param)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON payload"}), 400

        # Validate the structure of the payload.  Expect a dictionary with a 'name' key.
        if not isinstance(payload, dict) or 'name' not in payload:
            return jsonify({"error": "Payload must be a dictionary with a 'name' key"}), 400

        name = payload['name']

        # Sanitize the 'name' value.  This is crucial to prevent XSS.
        # Only allow alphanumeric characters and spaces.
        if not isinstance(name, str):
            return jsonify({"error": "Name must be a string"}), 400

        sanitized_name = ''.join(c for c in name if c.isalnum() or c.isspace())

        return jsonify({"name": sanitized_name})

    except Exception as e:
        # Log the error for debugging purposes (important for production).
        print(f"An error occurred: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500


@app.route('/form', methods=['GET', 'POST'])
def form_example():
    """
    Example form with CSRF protection using a nonce.
    """
    if request.method == 'GET':
        # Generate a unique nonce for the form.
        session['csrf_token'] = secrets.token_hex(16)
        return f'''
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
                <label for="name">Name:</label>
                <input type="text" id="name" name="name"><br><br>
                <input type="submit" value="Submit">
            </form>
        '''
    elif request.method == 'POST':
        # Validate the CSRF token.
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != session.pop('csrf_token', None):
            return jsonify({"error": "CSRF token is invalid"}), 400

        name = request.form.get('name')

        # Sanitize the name input (same as in the /api route).
        if not isinstance(name, str):
            return jsonify({"error": "Name must be a string"}), 400

        sanitized_name = ''.join(c for c in name if c.isalnum() or c.isspace())

        return jsonify({"message": f"Hello, {sanitized_name}!"})


@app.route('/redirect')
def redirect_example():
    """
    Example of a redirect, with URL validation to prevent open redirects.
    """
    next_url = request.args.get('next')

    if not next_url:
        return jsonify({"error": "Missing 'next' parameter"}), 400

    if is_valid_url(next_url):
        return f"Redirecting to: {next_url}" # In a real app, use redirect(next_url)
    else:
        return jsonify({"error": "Invalid redirect URL"}), 400


if __name__ == '__main__':
    # Never run this in production.  Use a proper WSGI server like Gunicorn or uWSGI.
    app.run(debug=True)

