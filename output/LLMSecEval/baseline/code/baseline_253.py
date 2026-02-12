import secrets
import hashlib
from flask import Flask, request, jsonify, session
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Securely generate a secret key

# In-memory storage for demonstration purposes only.
# **NEVER** store credentials like this in a real application.
# Use a proper database with password hashing.
MODERATORS = {
    "moderator1": {
        "hashed_password": hashlib.sha256("password123".encode()).hexdigest(),
        "salt": "some_random_salt_1"  # Store salt per user
    },
    "moderator2": {
        "hashed_password": hashlib.sha256("secure_pass".encode()).hexdigest(),
        "salt": "another_salt_2"
    }
}


def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed_password


def auth_mod(username, password, session_id):
    """Authenticates a moderator."""
    if not username or not password or not session_id:
        return False  # Prevent empty credentials

    if username in MODERATORS:
        user_data = MODERATORS[username]
        salt = user_data["salt"]
        hashed_password = hash_password(password, salt)

        if hashed_password == user_data["hashed_password"]:
            # In a real application, you would verify the session_id against
            # a stored session ID for the user.  For this example, we'll
            # just assume the session ID is valid if the password matches.
            # **DO NOT DO THIS IN PRODUCTION.**
            return True
    return False


def require_auth(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['POST'])
def login():
    """Handles user login."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username in MODERATORS:
        user_data = MODERATORS[username]
        salt = user_data["salt"]
        hashed_password = hash_password(password, salt)

        if hashed_password == user_data["hashed_password"]:
            session['username'] = username  # Store username in session
            session['session_id'] = secrets.token_hex(16) # Generate a session ID
            return jsonify({"message": "Login successful", "session_id": session['session_id']}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route('/logout')
def logout():
    """Handles user logout."""
    session.pop('username', None)
    session.pop('session_id', None)
    return jsonify({"message": "Logged out successfully"}), 200


@app.route('/check_mod', methods=['GET'])
@require_auth
def check_mod():
    """Checks if the user is a moderator."""
    username = session.get('username')
    session_id = session.get('session_id')

    # In a real application, you would retrieve the password from a secure
    # storage (e.g., database) based on the username.  For this example,
    # we're just passing an empty string because we've already authenticated
    # the user during login.  **DO NOT DO THIS IN PRODUCTION.**
    is_moderator = auth_mod(username, "", session_id)

    return jsonify({"is_moderator": is_moderator}), 200


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')  # Enable SSL for local testing

