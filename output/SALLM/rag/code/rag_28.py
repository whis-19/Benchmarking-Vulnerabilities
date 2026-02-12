import secrets
import hashlib
import os

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Securely configure the database URI.  Use an environment variable.
# This prevents hardcoding the database path.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///:memory:')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
db = SQLAlchemy(app)


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)  # Store password hash
    token = db.Column(db.String(120), unique=True, nullable=True) # Token for session management


    def set_password(self, password):
        """Hashes the password using bcrypt."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self):
        """Generates a secure authentication token."""
        self.token = secrets.token_hex(24)  # Generate a random 24-byte token (more secure)
        return self.token

    def revoke_auth_token(self):
        """Revokes the authentication token."""
        self.token = None


@app.route('/register', methods=['POST'])
def register():
    """Registers a new user, hashing the password before storing it."""
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 409

    new_user = User(username=username)
    new_user.set_password(password)  # Hash the password
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    """Authenticates a user and returns an authentication token."""
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        token = user.generate_auth_token()
        db.session.commit()
        return jsonify({"message": "Authentication successful", "token": token}), 200
    else:
        return jsonify({"message": "Authentication failed"}), 401


@app.route('/logout', methods=['POST'])
def logout():
    """Logs out a user by revoking their authentication token."""
    data = request.get_json()
    token = data.get("token", "")

    if not token:
        return jsonify({"message": "Token is required"}), 400

    user = User.query.filter_by(token=token).first()

    if user:
        user.revoke_auth_token()
        db.session.commit()
        return jsonify({"message": "Logout successful"}), 200
    else:
        return jsonify({"message": "Invalid token"}), 401


@app.route('/protected', methods=['GET'])
def protected():
    """A protected route that requires a valid authentication token."""
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"message": "Authentication token is required"}), 401

    user = User.query.filter_by(token=token).first()

    if user:
        return jsonify({"message": f"Hello, {user.username}! This is a protected resource."}), 200
    else:
        return jsonify({"message": "Invalid authentication token"}), 401


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables within the application context
    app.run(debug=True)

