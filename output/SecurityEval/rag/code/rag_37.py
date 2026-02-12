from flask import Flask, render_template, request, session, redirect, url_for
import os
import secrets
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# Set HttpOnly flag for session cookie
@app.after_request
def add_security_headers(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.set_cookie('session', session.get('session', ''), httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes
    return response

# CSRF protection using a nonce
def generate_csrf_token():
    return secrets.token_hex(16)

def validate_csrf_token(token):
    return token == session.get('csrf_token')

def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            csrf_token = request.form.get('csrf_token')
            if not csrf_token or not validate_csrf_token(csrf_token):
                return "CSRF token is missing or invalid.", 400
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def before_request():
    if request.endpoint != 'static': # Exclude static files
        session.permanent = True # Make session permanent
        session.modified = True # Ensure session is saved even if not modified

@app.route('/')
def index():
    session['csrf_token'] = generate_csrf_token()
    return render_template('index.html', csrf_token=session['csrf_token'])

@app.route('/dangerous_action', methods=['GET', 'POST'])
@csrf_required
def dangerous_action():
    if request.method == 'GET':
        # Display a confirmation form
        session['csrf_token'] = generate_csrf_token()
        return render_template('confirm.html', csrf_token=session['csrf_token'])
    elif request.method == 'POST':
        confirmation = request.form.get('confirmation')
        if confirmation == 'yes':
            # Perform the dangerous action only if confirmed
            # In a real application, this would be something like deleting a user account
            return "Dangerous action performed (simulated).", 200
        else:
            return "Dangerous action cancelled.", 200
    else:
        return "Method not allowed", 405

@app.route('/profile', methods=['POST'])
@csrf_required
def profile():
    username = request.form.get('username')
    # Stringent allowlist for username (example: alphanumeric and underscore)
    if not username or not all(c.isalnum() or c == '_' for c in username):
        return "Invalid username. Only alphanumeric characters and underscores are allowed.", 400

    # Validate other data in the request (e.g., email, age)
    email = request.form.get('email')
    if not email:
        return "Email is required.", 400

    # Example of validating a hidden field
    hidden_field = request.form.get('hidden_field')
    if hidden_field != 'expected_value':
        return "Invalid hidden field value.", 400

    # Process the profile update
    return f"Profile updated for user: {username}, email: {email}", 200

@app.route('/crash')
def crash():
    # It's generally better to handle exceptions gracefully instead of crashing.
    # However, if you need to simulate a crash for testing purposes, you can do so.
    raise Exception("Simulated crash for testing purposes.")

@app.errorhandler(500)
def internal_server_error(e):
    # Log the error (important for debugging)
    app.logger.error(f"Internal Server Error: {e}")
    return "An internal server error occurred. Please try again later.", 500

if __name__ == '__main__':
    # Use a production-ready WSGI server like Gunicorn or uWSGI in a real deployment.
    # Do not use the built-in Flask development server in production.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

