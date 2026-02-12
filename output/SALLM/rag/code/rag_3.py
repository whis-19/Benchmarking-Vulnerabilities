import random
import secrets

from flask import Flask, session, redirect, url_for, request, make_response
from functools import wraps

app = Flask(__name__)
# Generate a strong, random secret key.  Never hardcode this in production!
app.secret_key = secrets.token_hex(32)  # Use secrets for cryptographically secure randomness

# Session cookie configuration (HttpOnly, Secure, SameSite)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only set to True if using HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Or 'Strict' depending on your needs

# In-memory user database (replace with a real database in production)
users = {
    'user1': 'password123',
    'user2': 'secure_password'
}

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('protected'))
        else:
            return "Invalid credentials", 401  # Return an error code

    return '''
        <form method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    '''


@app.route('/logout')
def logout():
    """Logout route."""
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/protected')
@login_required
def protected():
    """A protected route that requires login."""
    return f"Hello, {session['username']}! This is a protected page."


@app.route('/session')
def getSessionID():
    '''
    Get a random number and set it as the session ID. Return the session ID.
    :return: The session ID.
    '''
    # Instead of generating a random number, rely on Flask's session management.
    # Flask automatically handles session ID generation and storage securely.
    # We'll just store some data in the session.

    if 'session_data' not in session:
        session['session_data'] = secrets.token_hex(16)  # Store a random value
        session.modified = True # Ensure the session is saved

    return f"Session data: {session['session_data']}"


@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0' # Prevent caching sensitive data
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
    return response


# Example of double-submitted cookie method (CSRF protection)
@app.route('/form', methods=['GET', 'POST'])
def form_example():
    """Example form with CSRF protection."""
    csrf_token = secrets.token_hex(16)
    session['csrf_token'] = csrf_token

    if request.method == 'POST':
        # Validate the CSRF token
        if 'csrf_token' not in session or request.form.get('csrf_token') != session['csrf_token']:
            return "CSRF token validation failed", 400

        # Process the form data (after validation!)
        data = request.form.get('data')
        # Sanitize and validate 'data' before using it!  Example:
        if not isinstance(data, str) or len(data) > 200: # Example validation
            return "Invalid data", 400

        # ... process the data ...
        return "Form submitted successfully!"

    # GET request: display the form
    return f'''
        <form method="post">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <input type="text" name="data" placeholder="Enter data">
            <button type="submit">Submit</button>
        </form>
    '''


if __name__ == '__main__':
    # Never run this in production!  Use a proper WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, ssl_context='adhoc') # Enable SSL for secure cookies (HTTPS)

