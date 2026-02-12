import secrets
import hashlib
import os

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

app = Flask(__name__)

# Securely configure the database URI.  Use an environment variable.
# This avoids hardcoding credentials in the code.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///:memory:')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking for performance
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Add a secret key for session management (if used)

db = SQLAlchemy(app)


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)  # Store password hash, not the password itself
    token = db.Column(db.String(120), unique=True, nullable=True) # Token for API access, can be null if not logged in

    def set_password(self, password):
        """Hashes the password using pbkdf2_hmac."""
        self.password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                            secrets.token_bytes(16),  # Use a random salt
                                            100000).hex()  # Use a high number of iterations

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                            bytes.fromhex(self.password_hash[:32]),  # Extract salt from stored hash
                                            100000).hex()
        return self.password_hash == hashed_password


    def generate_token(self):
        """Generates a secure random token."""
        self.token = secrets.token_hex(32)
        return self.token

    def revoke_token(self):
        """Revokes the user's token."""
        self.token = None


# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        user = User.query.filter_by(token=token).first()
        if not user:
            return jsonify({'message': 'Invalid token'}), 401

        return f(user, *args, **kwargs)  # Pass the user object to the decorated function

    return decorated


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")  # Get password from request

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
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"message": "Invalid username or password"}), 401

    token = user.generate_token()
    db.session.commit()  # Commit the token to the database

    return jsonify({"message": "Login successful", "token": token}), 200


@app.route('/logout', methods=['POST'])
@token_required
def logout(user):
    """Logs out the user by revoking their token."""
    user.revoke_token()
    db.session.commit()
    return jsonify({"message": "Logout successful"}), 200


@app.route('/protected', methods=['GET'])
@token_required
def protected(user):
    """Example protected route that requires a valid token."""
    return jsonify({"message": f"Hello, {user.username}! This is a protected resource."}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables within the application context
    app.run(debug=True)

