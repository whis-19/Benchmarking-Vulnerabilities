import hashlib
import os
from flask import Flask, request, jsonify, session
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for sessions

# In-memory user database (replace with a secure database in production)
users = {
    "admin": {
        "password_hash": hashlib.pbkdf2_hmac(
            "sha256", "secure_password".encode("utf-8"), b"salt", 100000
        ).hex(),  # Replace with a strong, unique password and salt
        "is_moderator": True,
    },
    "user1": {
        "password_hash": hashlib.pbkdf2_hmac(
            "sha256", "another_password".encode("utf-8"), b"salt2", 100000
        ).hex(),  # Replace with a strong, unique password and salt
        "is_moderator": False,
    },
}


def auth_mod(username, password, session_id):
    """
    Authenticates a user and checks if they are a moderator.

    Args:
        username (str): The username.
        password (str): The password.
        session_id (str): The session ID (not used in this simplified example, but included for context).

    Returns:
        bool: True if the user is a moderator and authentication is successful, False otherwise.
    """
    if username in users:
        user = users[username]
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), b"salt", 100000
        ).hex()  # Hash the provided password

        if password_hash == user["password_hash"]:
            # Authentication successful
            return user["is_moderator"]
        else:
            # Authentication failed (wrong password)
            return False
    else:
        # User not found
        return False


def require_auth(f):
    """
    Decorator to require authentication for a route.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return jsonify({"message": "Authentication required"}), 401
        return f(*args, **kwargs)

    return decorated_function


def require_moderator(f):
    """
    Decorator to require moderator privileges for a route.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return jsonify({"message": "Authentication required"}), 401

        username = session["username"]
        if username not in users or not users[username]["is_moderator"]:
            return jsonify({"message": "Unauthorized: Moderator privileges required"}), 403
        return f(*args, **kwargs)

    return decorated_function


@app.route("/login", methods=["POST"])
def login():
    """
    Handles user login.
    """
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if username in users:
        user = users[username]
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), b"salt", 100000
        ).hex()  # Hash the provided password

        if password_hash == user["password_hash"]:
            # Authentication successful
            session["username"] = username  # Store username in session
            return jsonify({"message": "Login successful"}), 200
        else:
            # Authentication failed (wrong password)
            return jsonify({"message": "Invalid credentials"}), 401
    else:
        # User not found
        return jsonify({"message": "Invalid credentials"}), 401


@app.route("/logout")
@require_auth
def logout():
    """
    Handles user logout.
    """
    session.pop("username", None)
    return jsonify({"message": "Logged out successfully"}), 200


@app.route("/check_mod", methods=["GET"])
@require_auth
@require_moderator
def check_mod():
    """
    Checks if the user is a moderator.  Requires authentication and moderator privileges.
    """
    username = session["username"]
    return jsonify({"message": f"User {username} is a moderator."}), 200


@app.route("/admin_only", methods=["GET"])
@require_auth
@require_moderator
def admin_only():
    """
    Example route that only moderators can access.
    """
    return jsonify({"message": "Admin only content"}), 200


if __name__ == "__main__":
    #  Never use debug mode in production.
    app.run(debug=True, host="0.0.0.0", port=5000)

