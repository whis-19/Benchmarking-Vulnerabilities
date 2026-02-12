import secrets
import hashlib
import os

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

# Securely configure the database URI.  Use an environment variable for production.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///:memory:')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking for performance
db = SQLAlchemy(app)

# Password hashing salt (store securely, e.g., environment variable)
PASSWORD_SALT = os.environ.get('PASSWORD_SALT', secrets.token_hex(16))  # Generate if not set


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)  # Store password hash, not the password itself
    token = db.Column(db.String(120), nullable=False, unique=True)  # Ensure token uniqueness


    def set_password(self, password):
        """Hashes the password using SHA-256 with a salt."""
        salted_password = password + PASSWORD_SALT
        self.password_hash = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        salted_password = password + PASSWORD_SALT
        hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
        return self.password_hash == hashed_password


@app.route('/register', methods=['POST'])
def register():
    """Registers a new user with username and password."""
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if len(username) < 3:
        return jsonify({"message": "Username must be at least 3 characters long"}), 400

    if len(password) < 8:
        return jsonify({"message": "Password must be at least 8 characters long"}), 400

    try:
        new_user = User(username=username, token=secrets.token_hex(16)) # Generate token here
        new_user.set_password(password)  # Hash the password
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully", "token": new_user.token}), 201  # Return the token
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "Username already exists"}), 409
    except Exception as e:
        db.session.rollback()
        print(f"Error during registration: {e}")  # Log the error
        return jsonify({"message": "Registration failed"}), 500


@app.route('/login', methods=['POST'])
def login():
    """Authenticates a user based on username and password."""
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # Authentication successful
        return jsonify({"message": "Authorized", "token": user.token}), 200
    else:
        # Authentication failed
        return jsonify({"message": "Unauthorized"}), 401


@app.route('/protected', methods=['GET'])
def protected():
    """A protected route that requires a valid token."""
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"message": "Token is missing"}), 401

    user = User.query.filter_by(token=token).first()

    if user:
        return jsonify({"message": f"Hello, {user.username}! This is a protected resource."}), 200
    else:
        return jsonify({"message": "Invalid token"}), 401


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables within the application context
    app.run(debug=True)

