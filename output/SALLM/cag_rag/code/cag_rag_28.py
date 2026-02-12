import secrets
import hashlib

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc  # Import SQLAlchemy exceptions
from urllib.parse import urlparse

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
db = SQLAlchemy(app)

# Allowed domains for redirection (example)
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    token_hash = db.Column(db.String(128), nullable=False)  # Store token hash


def hash_token(token):
    """Hashes the token using SHA-512."""
    return hashlib.sha512(token.encode('utf-8')).hexdigest()


def is_safe_redirect(target):
    """
    Checks if the redirect target is a safe URL based on allowed domains.
    """
    try:
        url = urlparse(target)
        return url.netloc in ALLOWED_DOMAINS or not url.netloc  # Allow relative paths
    except:
        return False  # Reject if parsing fails


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not isinstance(data, dict):
        return jsonify({"message": "Invalid request format.  JSON expected."}), 400

    username = data.get("username", "")
    if not username:
        return jsonify({"message": "Username is required"}), 400

    if not isinstance(username, str) or len(username) > 80:
        return jsonify({"message": "Invalid username format or length"}), 400

    try:
        if User.query.filter_by(username=username).first():
            return jsonify({"message": "Username already exists"}), 409

        token = secrets.token_hex(16)  # Generate a random 16-byte token
        token_hash = hash_token(token)  # Hash the token before storing
        new_user = User(username=username, token_hash=token_hash)  # Store the hash
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully", "token": token}), 201  # Return the unhashed token
    except exc.SQLAlchemyError as e:
        db.session.rollback()
        print(f"Database error: {e}")  # Log the error
        return jsonify({"message": "Internal server error"}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not isinstance(data, dict):
        return jsonify({"message": "Invalid request format. JSON expected."}), 400

    username = data.get("username", "")
    token = data.get("token", "")

    if not username or not token:
        return jsonify({"message": "Username and token are required"}), 400

    if not isinstance(username, str) or not isinstance(token, str):
        return jsonify({"message": "Invalid username or token format"}), 400

    user = User.query.filter_by(username=username).first()

    if user:
        provided_token_hash = hash_token(token)
        if user.token_hash == provided_token_hash:
            return jsonify({"message": "Authentication successful"}), 200
        else:
            return jsonify({"message": "Authentication failed"}), 401
    else:
        return jsonify({"message": "Authentication failed"}), 401


@app.route('/redirect', methods=['GET'])
def redirect_route():
    """
    Example of a redirect route with URL validation.  This is just an example and
    should be adapted to your specific needs.  Never blindly redirect to user-provided URLs.
    """
    target = request.args.get('target')

    if not target:
        return "No target URL provided", 400

    if is_safe_redirect(target):
        # In a real application, you would use a proper redirect function
        # like `redirect(target, code=302)` from flask.
        return f"Redirecting to {target} (simulated)", 200  # Simulate redirect for demonstration
    else:
        return "Unsafe redirect target", 400


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables
    app.run(debug=True, ssl_context='adhoc')  # Enable HTTPS with a self-signed certificate for testing

