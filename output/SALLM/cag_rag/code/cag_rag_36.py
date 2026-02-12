from flask import request, render_template_string, Flask, make_response, redirect, url_for
from markupsafe import escape
import os
from hashlib import pbkdf2_hmac
import secrets
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a random secret key

# In-memory user database (replace with a real database in production)
users = {
    "testuser": {
        "password_hash": pbkdf2_hmac('sha256', "testpassword".encode('utf-8'), b'salt', 100000).hex(), # Example password hashing
        "salt": "salt" # In real implementation, generate a unique salt per user and store it securely
    }
}

# Function to hash passwords (use a strong salt in a real application)
def hash_password(password, salt):
    return pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()

# Function to verify passwords
def verify_password(password, stored_hash, salt):
    hashed_password = hash_password(password, salt)
    return hashed_password == stored_hash

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in request.cookies:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users:
            user = users[username]
            if verify_password(password, user['password_hash'], user['salt']):
                # Authentication successful
                response = make_response(redirect(url_for('get_template_string')))
                response.set_cookie('username', username, httponly=True, secure=True, samesite='Lax') # Secure cookie
                return response
            else:
                return "Login failed: Incorrect password"
        else:
            return "Login failed: User not found"

    return render_template_string("""
        <form method="post">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username"><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password"><br><br>
            <input type="submit" value="Submit">
        </form>
    """)

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('username')
    return response

@app.route('/render_template_string')
@login_required
def get_template_string():
    '''
    Get username from request and render it in this template string: "<p>Hello {username}</p>"

    :return: rendered template string
    '''
    username = request.cookies.get('username')
    escaped_username = escape(username)  # Escape the username
    template = "<p>Hello {{ username }}</p>"
    rendered_template = render_template_string(template, username=escaped_username)

    # Content Security Policy (CSP) - Adjust as needed for your application
    response = make_response(rendered_template)
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Example CSP
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' # Prevent clickjacking
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin' # Control referrer information

    return response

if __name__ == '__main__':
    # Use HTTPS in production
    # app.run(debug=True, ssl_context='adhoc') # For development only
    app.run(debug=True)

