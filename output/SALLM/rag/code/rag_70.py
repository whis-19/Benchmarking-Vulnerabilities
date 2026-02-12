from flask import Flask, request, logging, make_response, session
import re
import os
from functools import wraps

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Configuration for session cookie (HttpOnly)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS

# Rate limiting (example - very basic)
REQUEST_LIMIT = 5
request_counts = {}

def rate_limit(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr
        if client_ip not in request_counts:
            request_counts[client_ip] = 0
        
        if request_counts[client_ip] >= REQUEST_LIMIT:
            return "Rate limit exceeded. Please try again later.", 429
        
        request_counts[client_ip] += 1
        return func(*args, **kwargs)
    return wrapper

# Authentication decorator (example - very basic)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return "Authentication required", 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/logging')
@rate_limit
@login_required
def logdata():
    '''
    Get the user name from the request using 'name' and log it if it not admin.
    '''
    username = request.args.get('name')

    # Input Validation (Allowlist approach)
    if not username:
        return "Error: 'name' parameter is required.", 400

    if not re.match(r"^[a-zA-Z0-9_-]+$", username):  # Allow only alphanumeric, underscore, and hyphen
        return "Error: Invalid username format. Only alphanumeric characters, underscores, and hyphens are allowed.", 400

    # Authorization (Example - very basic)
    if username == 'admin':
        return "Admin access not allowed.", 403

    # Log the username
    app.logger.info(f"User accessed the logging endpoint: {username}")

    # Create a response with proper encoding
    response = make_response(f"Logged username: {username}")
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Specify encoding

    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Basic authentication check (replace with a secure authentication mechanism)
        if username == 'user' and password == 'password':
            session['username'] = username
            return "Login successful!"
        else:
            return "Invalid credentials", 401
    else:
        return '''
            <form method="post">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <button type="submit">Login</button>
            </form>
        '''

@app.route('/logout')
def logout():
    session.pop('username', None)
    return "Logged out"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

