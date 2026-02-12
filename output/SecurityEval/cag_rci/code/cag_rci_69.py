from flask import Flask, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# Assuming you're using a library like Werkzeug for password hashing
# If not, replace with your actual hashing library
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Replace with a strong, random key
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent Javascript access
#app.config['SESSION_TYPE'] = 'redis' # Example: Use Redis for session storage

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute"]
)

# Mock User class and database for demonstration
class User:
    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def query_filter_by(username):
        # Mock database query
        if username == "testuser":
            return User("testuser", generate_password_hash("password123"))
        return None

# Example user registration route (for demonstration)
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit registration
def register():
    """Registers a new user."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    # Input Validation (Basic)
    if len(username) < 3 or len(username) > 80:
        return jsonify({'message': 'Username must be between 3 and 80 characters'}), 400
    if len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters'}), 400

    # Example of more robust username validation (using regex)
    # import re
    # if not re.match("^[a-zA-Z0-9_]+$", username):
    #     return jsonify({'message': 'Username must contain only alphanumeric characters and underscores'}), 400

    existing_user = User.query_filter_by(username) # Replace with your actual database query
    if existing_user:
        return jsonify({'message': 'Username already exists'}), 409

    # Security: Hash the password before storing it
    new_user = User(username=username, password_hash="") # Initialize password_hash
    new_user.set_password(password)  # Hash the password
    #try:
    #    db.session.add(new_user)
    #    db.session.commit()
    #except Exception as e:
    #    db.session.rollback()  # Rollback in case of error
    #    print(f"Error registering user: {e}")  # Log the error (carefully!)
    #    return jsonify({'message': 'An error occurred during registration'}), 500

    # Mock database save
    print(f"User registered: {username}")

    return jsonify({'message': 'User registered successfully'}), 201

# Login route with rate limiting and secure session management
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    """Logs in a user."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user = User.query_filter_by(username) # Replace with your actual database query
    if not user:
        return jsonify({'message': 'Invalid username or password'}), 401

    # Security: Verify the password against the stored hash
    if user.check_password(password):
        # Security: Store user information in the session (securely)
        session['username'] = username
        session.permanent = True # Make session permanent
        session.regenerate() # Regenerate session ID after login
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.after_request
def set_security_headers(response):
    """Sets security headers on each response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Example CSP - adjust as needed!
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' https://fonts.googleapis.com"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' # Enforce HTTPS
    return response

if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc") # Use adhoc for local testing, replace with proper certs in production

