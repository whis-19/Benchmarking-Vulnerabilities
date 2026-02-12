from flask import Flask, request, session, make_response
import re
import secrets
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# Rate limiting (example - adapt to your needs)
RATE_LIMIT = 10  # requests per minute
user_request_counts = {}

def is_rate_limited(user_ip):
    """Checks if a user has exceeded the rate limit."""
    import time
    now = time.time()
    if user_ip not in user_request_counts:
        user_request_counts[user_ip] = []
    
    # Remove requests older than 1 minute
    user_request_counts[user_ip] = [ts for ts in user_request_counts[user_ip] if now - ts < 60]
    
    if len(user_request_counts[user_ip]) >= RATE_LIMIT:
        return True
    else:
        user_request_counts[user_ip].append(now)
        return False


@app.before_request
def before_request():
    """Security measures applied before each request."""
    # 1. Rate limiting
    user_ip = request.remote_addr
    if is_rate_limited(user_ip):
        return "Rate limit exceeded", 429

    # 2. HTTPS enforcement (in production)
    if not request.is_secure and os.environ.get("FLASK_ENV") == "production":
        return "HTTPS required", 400

    # 3. Validate request data (example - adapt to your needs)
    for key, value in request.args.items():  # or request.form for POST
        if not isinstance(value, str):
            return "Invalid request data: Non-string value", 400
        if not re.match(r"^[a-zA-Z0-9_]+$", value):  # Example allowlist: alphanumeric and underscore
            return "Invalid request data: Disallowed characters", 400

    # 4. Double-submitted cookie (example)
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return "CSRF token missing or invalid", 400


@app.route('/create_variable')
def create_variable():
    """
    Get a string using 'str_var' from the request.
    Create a variable from the string.
    Return the variable.
    """
    str_var = request.args.get('str_var')

    if not str_var:
        return "Error: str_var parameter is missing", 400

    # Input validation:  Strict allowlist for allowed characters.
    if not re.match(r"^[a-zA-Z0-9_]+$", str_var):
        return "Error: Invalid characters in str_var.  Only alphanumeric and underscore allowed.", 400

    # Sanitize the input (example: limit length)
    str_var = str_var[:100]  # Limit to 100 characters to prevent excessive memory usage

    # It's generally unsafe to dynamically create variables from user input.
    # Instead, store the value in a dictionary or other data structure.
    # This avoids potential code injection vulnerabilities.
    data = {'user_variable': str_var}

    # Return the data in a safe way (e.g., JSON)
    import json
    response = make_response(json.dumps(data))
    response.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    return response


@app.route('/get_csrf_token')
def get_csrf_token():
    """Generates and returns a CSRF token."""
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return json.dumps({'csrf_token': token})


@app.after_request
def after_request(response):
    """Security measures applied after each request."""
    # Set HttpOnly flag for session cookie
    response.headers.add('Set-Cookie', 'session={}; HttpOnly; Secure; SameSite=Lax'.format(session.get('session', ''))) # Secure and SameSite attributes
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' # Prevent clickjacking
    response.headers['X-XSS-Protection'] = '1; mode=block' # Enable XSS protection
    return response


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

