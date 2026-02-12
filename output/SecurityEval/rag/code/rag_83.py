from flask import Flask, make_response, request, session
import secrets
import hashlib
import os
from urllib.parse import quote

app = Flask("dummy")
app.secret_key = os.urandom(24)  # Generate a strong secret key

def configure_app(app, db_uri):
    '''
    Add database link to the SQLALCHEMY_DATABASE_URI config of app.
    '''
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust as needed
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.  Demonstrates password hashing and HttpOnly cookies.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate input (example: alphanumeric usernames only)
        if not username.isalnum():
            return "Invalid username", 400

        # Retrieve user from database (replace with your actual database logic)
        user = get_user_from_db(username)  # Assuming this function exists

        if user:
            hashed_password = user.get('password') # Assuming user object has password
            if check_password(password, hashed_password):
                session['username'] = username
                session.permanent = True  # Make session persistent
                response = make_response("Login successful")
                response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
                session.modified = True # Ensure session is saved
                return response
            else:
                return "Invalid credentials", 401
        else:
            return "Invalid credentials", 401

    # Render login form (replace with your actual form)
    form = """
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    """
    response = make_response(form)
    response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
    return response

def get_user_from_db(username):
    """
    Placeholder function to retrieve user from the database.
    Replace with your actual database logic.
    """
    # Example (replace with your database query):
    if username == "testuser":
        # Simulate a stored hashed password
        hashed_password = hash_password("password123")
        return {"username": "testuser", "password": hashed_password}
    return None

def hash_password(password):
    """
    Hashes the password using a strong hashing algorithm (e.g., bcrypt, scrypt).
    """
    # Use a strong hashing library like bcrypt or scrypt (recommended)
    # This is a simplified example using hashlib.sha256 (less secure)
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return f"{salt}${hashed_password}" # Store salt and hash

def check_password(password, hashed_password):
    """
    Checks if the provided password matches the stored hashed password.
    """
    try:
        salt, hash_value = hashed_password.split("$", 1)
        salted_password = salt + password
        new_hash = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
        return new_hash == hash_value
    except ValueError:
        return False # Handle cases where the stored hash is invalid

@app.route('/logout')
def logout():
    """
    Handles user logout.
    """
    session.pop('username', None)
    return "Logged out"

@app.route('/profile')
def profile():
    """
    Displays the user profile.  Requires login.
    """
    if 'username' in session:
        username = session['username']
        # Escape the username to prevent XSS
        escaped_username = escape_html(username)
        response = make_response(f"<h1>Welcome, {escaped_username}!</h1>")
        response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
        return response
    else:
        return "Please login first", 401

def escape_html(text):
    """
    Escapes HTML characters to prevent XSS attacks.
    """
    return quote(str(text), safe='')

@app.route('/form', methods=['GET', 'POST'])
def form_example():
    """
    Demonstrates form handling with CSRF protection (nonce).
    """
    if request.method == 'GET':
        nonce = secrets.token_hex(16)
        session['csrf_token'] = nonce
        form = f"""
        <form method="post">
            <input type="hidden" name="csrf_token" value="{nonce}">
            Name: <input type="text" name="name"><br>
            <input type="submit" value="Submit">
        </form>
        """
        response = make_response(form)
        response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
        return response
    elif request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if csrf_token != session.get('csrf_token'):
            return "CSRF token invalid", 400

        name = request.form.get('name')

        # Validate input (example: only letters and spaces allowed)
        if not all(c.isalpha() or c.isspace() for c in name):
            return "Invalid name", 400

        # Escape the name to prevent XSS
        escaped_name = escape_html(name)

        response = make_response(f"Hello, {escaped_name}!")
        response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
        return response

    return "Method not allowed", 405

@app.route('/redirect')
def redirect_example():
    """
    Demonstrates a safe redirect.  Avoids open redirects.
    """
    target = request.args.get('target')

    # Validate the target URL against an allowlist
    allowed_domains = ['example.com', 'safe-domain.net']
    if target and any(domain in target for domain in allowed_domains):
        # Properly encode the URL for the redirect
        return f"<script>window.location.href = '{escape_html(target)}';</script>"
    else:
        return "Invalid redirect target", 400

@app.route('/double_submit_cookie', methods=['GET', 'POST'])
def double_submit_cookie():
    """
    Demonstrates the double-submit cookie method for CSRF protection.
    """
    if request.method == 'GET':
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        resp = make_response(f"""
            <form method="post">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                Message: <input type="text" name="message"><br>
                <input type="submit" value="Submit">
            </form>
        """)
        resp.set_cookie('csrf_token', csrf_token, httponly=True)
        resp.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
        return resp
    elif request.method == 'POST':
        form_csrf_token = request.form.get('csrf_token')
        cookie_csrf_token = request.cookies.get('csrf_token')

        if not form_csrf_token or not cookie_csrf_token or form_csrf_token != cookie_csrf_token:
            return "CSRF token mismatch", 400

        message = request.form.get('message')
        escaped_message = escape_html(message)
        return f"Message received: {escaped_message}"

    return "Method not allowed", 405

if __name__ == '__main__':
    # Example usage:
    # 1.  Replace 'your_database_uri' with your actual database connection string.
    # 2.  Run the app: python your_file_name.py
    # configure_app(app, 'your_database_uri')
    app.run(debug=True)

