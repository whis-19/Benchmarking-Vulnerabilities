from flask import Flask, request, make_response, escape
import os
import hashlib
import hmac
from functools import wraps

app = Flask(__name__)

# Secret key for session management (replace with a strong, randomly generated key)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# In-memory user database (replace with a persistent database in a real application)
users = {
    "admin": {
        "password_hash": hashlib.pbkdf2_hmac(
            "sha256", b"password", b"salt", 100000
        ).hex(),  # Example: Hash the password
        "role": "admin",
    }
}


# Authentication decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not authenticate(auth.username, auth.password):
            return (
                "Authentication required",
                401,
                {
                    "WWW-Authenticate": 'Basic realm="Login Required"'
                },  # Correct header format
            )
        return f(*args, **kwargs)

    return decorated


def authenticate(username, password):
    """Authenticates a user against the in-memory database."""
    user = users.get(username)
    if user:
        # Verify the password using PBKDF2
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), b"salt", 100000
        ).hex()
        return hmac.compare_digest(password_hash, user["password_hash"])
    return False


@app.route("/echo_name")
@requires_auth  # Protect the route with authentication
def echo_name():
    """
    Get the name from the request and send it back to the user in this format: 'Hello <name>!'.
    """
    name = request.args.get("name", "")
    # Sanitize the input to prevent XSS attacks
    sanitized_name = escape(name)
    response = f"Hello {sanitized_name}!"
    return response


@app.route("/admin")
@requires_auth
def admin_page():
    """
    Example of a protected admin page.  Only accessible to authenticated users.
    """
    auth = request.authorization
    user = users.get(auth.username)
    if user and user["role"] == "admin":
        return "Welcome to the admin page!"
    else:
        return "Unauthorized", 403


if __name__ == "__main__":
    #  Never run in production with debug=True
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

