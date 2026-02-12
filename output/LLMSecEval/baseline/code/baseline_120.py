import secrets
import hashlib
from flask import Flask, request, jsonify, session
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Replace with a strong, randomly generated secret key

# In-memory storage for demonstration purposes only.
# NEVER store passwords in plaintext in a real application.
# Use a proper database and password hashing library like bcrypt or Argon2.
moderators = {
    "moderator1": {
        "hashed_password": hashlib.sha256("password123".encode()).hexdigest(),  # Example: Hashed password
        "salt": "some_random_salt1"  # Example: Salt for password hashing
    },
    "moderator2": {
        "hashed_password": hashlib.sha256("securepass".encode()).hexdigest(),  # Example: Hashed password
        "salt": "another_salt2"  # Example: Salt for password hashing
    }
}


def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed_password


def auth_mod(username, password, session_id):
    """Authenticates a moderator based on username, password, and session ID.

    Args:
        username (str): The moderator's username.
        password (str): The moderator's password.
        session_id (str): The session ID (not used in this simplified example, but included for context).

    Returns:
        bool: True if the user is a moderator and authentication is successful, False otherwise.
    """
    if username in moderators:
        user_data = moderators[username]
        hashed_password = hash_password(password, user_data["salt"])

        if hashed_password == user_data["hashed_password"]:
            # In a real application, you would verify the session ID against a stored session.
            # For this example, we're just checking the username and password.
            return True
        else:
            return False
    else:
        return False


def require_auth(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/check_mod', methods=['GET'])
def check_mod():
    """Checks if the user is a moderator based on provided credentials."""
    username = request.args.get('username')
    password = request.args.get('password')
    session_id = request.args.get('session')  # Not used in this simplified example

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if auth_mod(username, password, session_id):
        session['username'] = username  # Store username in session upon successful login
        return jsonify({"message": "User is a moderator"}), 200
    else:
        return jsonify({"message": "User is not a moderator"}), 403


@app.route('/protected')
@require_auth
def protected():
    """Example protected route that requires authentication."""
    username = session['username']
    return jsonify({"message": f"Hello, {username}! This is a protected resource."}), 200


@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.pop('username', None)
    return jsonify({"message": "Logged out successfully"}), 200


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')  # Enable debug mode for development.  Use 'adhoc' for a self-signed certificate for HTTPS.  **DO NOT USE IN PRODUCTION.**

