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
    Validates the URL to prevent Server-Side Request Forgery (SSRF).
    This is a basic example and should be expanded based on your specific needs.
    """
    try:
        result = urlparse(url)
        # Check if the scheme is allowed (e.g., only allow https)
        if result.scheme != 'https':
            return False
        # Check if the hostname is in an allowlist (e.g., only allow your own domain)
        allowed_hosts = ['yourdomain.com', 'localhost']  # Replace with your allowed domains
        if result.hostname not in allowed_hosts:
            return False
        return True
    except:
        return False


@app.route('/api', methods=['GET'])
def api():
    """
    API endpoint that retrieves the 'name' value from a JSON payload passed in the URL.
    """
    payload_param = request.args.get('payload')

    if not payload_param:
        return jsonify({"error": "Payload parameter is missing"}), 400

    try:
        # Validate the payload parameter (string with alphanumeric and limited special characters)
        if not isinstance(payload_param, str) or not all(c.isalnum() or c in ['_', '-', '.'] for c in payload_param):
            return jsonify({"error": "Invalid payload parameter format"}), 400

        # Load the payload into a dictionary
        try:
            payload = json.loads(payload_param)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON payload"}), 400

        # Validate the structure of the payload (allowlist approach)
        if not isinstance(payload, dict) or 'name' not in payload:
            return jsonify({"error": "Invalid payload structure.  'name' field is required."}), 400

        name = payload.get('name')

        # Validate the 'name' value (string with alphanumeric and spaces only)
        if not isinstance(name, str) or not all(c.isalnum() or c.isspace() for c in name):
            return jsonify({"error": "Invalid 'name' value format"}), 400

        return jsonify({"name": name})

    except Exception as e:
        print(f"An unexpected error occurred: {e}")  # Log the error for debugging
        return jsonify({"error": "An unexpected error occurred"}), 500


# Example of using a nonce to prevent CSRF attacks (for POST requests - not used in this specific example, but good practice)
@app.route('/form', methods=['GET', 'POST'])
def form_example():
    nonce = secrets.token_hex(16)
    session['nonce'] = nonce

    if request.method == 'POST':
        submitted_nonce = request.form.get('nonce')
        if submitted_nonce != session.pop('nonce', None):
            return jsonify({"error": "CSRF token is invalid"}), 400

        # Process the form data here (after CSRF validation)
        # ...

        return jsonify({"message": "Form submitted successfully"})

    return f"""
    <form method="POST">
        <input type="hidden" name="nonce" value="{nonce}">
        <input type="text" name="data">
        <button type="submit">Submit</button>
    </form>
    """


if __name__ == '__main__':
    #  Never use debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

