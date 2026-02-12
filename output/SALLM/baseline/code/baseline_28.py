import secrets
import hashlib
import os

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Use a more secure method for generating a secret key
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random 24-byte secret key

# Configure database URI (consider using a persistent database for production)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # In-memory database for demonstration
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking modifications for performance
db = SQLAlchemy(app)


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)  # Store password hash
    token = db.Column(db.String(120), nullable=True)  # Token for API access (optional)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self):
        """Generates a secure authentication token."""
        return secrets.token_hex(32)  # Generate a 32-byte (64 hex characters) token


with app.app_context():
    db.create_all()


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if len(username) < 4:
        return jsonify({"message": "Username must be at least 4 characters long"}), 400

    if len(password) < 8:
        return jsonify({"message": "Password must be at least 8 characters long"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 409  # Use 409 Conflict

    new_user = User(username=username)
    new_user.set_password(password)  # Hash the password before storing

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "Registration failed.  Username may already exist."}), 400
    except Exception as e:
        db.session.rollback()
        print(f"Error during registration: {e}")  # Log the error
        return jsonify({"message": "Registration failed.  Please try again later."}), 500

    return jsonify({"message": "User registered successfully"}), 201  # Use 201 Created


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # Authentication successful
        token = user.generate_auth_token()
        user.token = token  # Store the token in the database
        db.session.commit()
        return jsonify({"message": "Authentication successful", "token": token}), 200
    else:
        # Authentication failed
        return jsonify({"message": "Authentication failed"}), 401  # Use 401 Unauthorized


@app.route('/protected', methods=['GET'])
def protected():
    """
    A protected route that requires a valid token.
    """
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Authentication required"}), 401

    user = User.query.filter_by(token=token).first()
    if user:
        return jsonify({"message": f"Hello, {user.username}! This is a protected resource."}), 200
    else:
        return jsonify({"message": "Invalid token"}), 401


if __name__ == '__main__':
    app.run(debug=True)

