from flask import Flask, request, make_response, session, jsonify
import secrets
import os
import re
import time
import logging

app = Flask(__name__)
# Securely generate a secret key and store it in an environment variable or secure configuration.
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(16)

# Max content length to prevent excessive memory usage
MAX_CONTENT_LENGTH = 1024  # Adjust as needed

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Configure logging
logging.basicConfig(level=logging.INFO)  # Or logging.DEBUG for more verbose output


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Content-Security-Policy'] = "default-src 'self';"  # Example CSP
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.route('/contents_json', methods=['POST'])
def contents_json():
    """
    Receives JSON data and validates it.
    """
    try:
        data = request.get_json()

        if not isinstance(data, dict):
            app.logger.warning("Invalid request: Request body must be a JSON dictionary.")
            return jsonify({"error": "Request body must be a JSON dictionary."}), 400

        # Example validation: Restrict key and value types and value ranges
        for key, value in data.items():
            if not isinstance(key, str):
                app.logger.warning(f"Invalid key type: Key '{key}' must be a string.")
                return jsonify({"error": f"Key '{key}' must be a string."}), 400
            if not isinstance(value, int):
                app.logger.warning(f"Invalid value type: Value '{value}' for key '{key}' must be an integer.")
                return jsonify({"error": f"Value '{value}' for key '{key}' must be an integer."}), 400
            if value < 0 or value > 100:
                app.logger.warning(f"Invalid value range: Value '{value}' for key '{key}' must be between 0 and 100.")
                return jsonify({"error": f"Value '{value}' for key '{key}' must be between 0 and 100."}), 400

        return jsonify(data), 200

    except Exception as e:
        app.logger.exception("Error processing JSON request")
        return jsonify({"error": "Error processing JSON request."}), 400


@app.route('/csrf_example', methods=['GET', 'POST'])
def csrf_example():
    """
    Demonstrates CSRF protection using a pseudorandom token with a time-based component.
    """
    if request.method == 'GET':
        # Generate a CSRF token and store it in the session and as a cookie
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = {'token': csrf_token, 'timestamp': time.time()}
        resp = make_response(f"""
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <button type="submit">Submit</button>
            </form>
        """)
        resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict')  # HttpOnly and SameSite
        return resp

    elif request.method == 'POST':
        # Validate the CSRF token
        form_csrf_token = request.form.get('csrf_token')
        session_csrf_data = session.get('csrf_token')

        if not session_csrf_data:
            app.logger.warning("CSRF token missing from session.")
            return "CSRF token validation failed.", 400

        session_csrf_token = session_csrf_data.get('token')
        session_csrf_timestamp = session_csrf_data.get('timestamp')

        if not session_csrf_token or not session_csrf_timestamp:
            app.logger.warning("CSRF token missing components in session.")
            return "CSRF token validation failed.", 400

        # Check token age (e.g., 15 minutes = 900 seconds)
        if time.time() - session_csrf_timestamp > 900:
            app.logger.warning("CSRF token expired.")
            return "CSRF token expired.", 400

        cookie_csrf_token = request.cookies.get('csrf_token')

        if not form_csrf_token or form_csrf_token != session_csrf_token or form_csrf_token != cookie_csrf_token:
            app.logger.warning("CSRF token mismatch.")
            return "CSRF token validation failed.", 400

        # Process the request (if CSRF token is valid)
        return "Request processed successfully!", 200
    else:
        return "Method not allowed", 405


if __name__ == '__main__':
    # Consider using a production WSGI server like gunicorn or uWSGI
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

