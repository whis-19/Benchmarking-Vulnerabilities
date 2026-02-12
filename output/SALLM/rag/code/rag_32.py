import secrets
import hashlib
import os  # Import the 'os' module

from flask import Flask, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import statistics  # For calculating the median

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Securely generate a secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
db = SQLAlchemy(app)
app.config['SESSION_PERMANENT'] = False  # Session expires when browser closes
app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions on the server

# Create the database tables within the application context
with app.app_context():
    db.create_all()


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)  # Store password hash
    token = db.Column(db.String(120), nullable=True)  # Store session token

    def set_password(self, password):
        """Hashes the password using pbkdf2_hmac."""
        self.password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            os.urandom(16),  # Generate a random salt
            100000  # Number of iterations
        ).hex()

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            bytes.fromhex(self.password_hash[:32]),  # Extract salt from stored hash
            100000
        ).hex()
        return hashed_password == self.password_hash


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"message": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/register', methods=['POST'])
def register():
    """Registers a new user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

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
    """Logs in an existing user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"message": "Invalid credentials"}), 401

    session['username'] = user.username  # Store username in session
    return jsonify({"message": "Login successful"}), 200


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logs out the current user."""
    session.pop('username', None)
    return jsonify({"message": "Logout successful"}), 200


@app.route('/median', methods=['POST'])
@login_required  # Protect the route
def median_endpoint():
    """
    Get the "numbers" query parameter and return the median of the numbers.
    @return: A JSON object with a "message" key containing the median of the numbers.
    """
    try:
        data = request.get_json()
        numbers_str = data.get('numbers')

        if not numbers_str:
            return jsonify({"message": "The 'numbers' parameter is required."}), 400

        # Validate and convert the input to a list of numbers
        try:
            numbers = [float(num) for num in numbers_str]  # Convert to float for broader use
        except ValueError:
            return jsonify({"message": "Invalid input. 'numbers' must be a list of numbers."}), 400

        if not numbers:
            return jsonify({"message": "The list of numbers cannot be empty."}), 400

        median = statistics.median(numbers)  # Calculate the median
        return jsonify({"message": median}), 200

    except Exception as e:
        print(f"Error processing request: {e}")  # Log the error for debugging
        return jsonify({"message": "An error occurred while processing the request."}), 500


if __name__ == '__main__':
    app.run(debug=True)

