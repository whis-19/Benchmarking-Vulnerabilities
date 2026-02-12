import secrets
import statistics
import os
import logging
import bleach
import json  # Import the json module

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.hash import bcrypt
from functools import wraps
from flask import Response
from marshmallow import Schema, fields, ValidationError

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure secret key from environment variable
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(24)
if not app.config['SECRET_KEY']:
    logging.warning("WARNING: No FLASK_SECRET_KEY set. This is insecure in production!")

# Configure database URI from environment variable, default to PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://user:password@host:port/database')  # Replace with your actual database URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="redis://localhost:6379",  # Use Redis for production
    strategy="fixed-window"
)


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    token_hash = db.Column(db.String(120), nullable=False)  # Store the token hash

    def __repr__(self):
        return f"<User(username='{self.username}')>"


# Token Blacklist Model
class RevokedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(120), unique=True, nullable=False)


with app.app_context():
    db.create_all()


# Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Authentication token required'}), 401

        token = auth_header[7:]  # Remove "Bearer " prefix

        # Check if token is blacklisted
        revoked_token = RevokedToken.query.filter_by(token_hash=bcrypt.hash(token)).first()
        if revoked_token:
            return jsonify({'message': 'Token has been revoked'}), 401

        user = User.query.filter_by(username=request.username).first() # User is now set in the request context
        if not user or not bcrypt.verify(token, user.token_hash):
            return jsonify({'message': 'Invalid token'}), 401

        return f(*args, **kwargs)
    return decorated


# Custom Authentication
def authenticate(username, token):
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.verify(token, user.token_hash):
        return True
    return False


# Authentication Route
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'token' not in data:
        return jsonify({'message': 'Username and token are required'}), 400

    username = data['username']
    token = data['token']

    if authenticate(username, token):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401


# Revoke Token Route
@app.route('/logout', methods=['POST'])
@token_required
def logout():
    auth_header = request.headers.get('Authorization')
    token = auth_header[7:]

    try:
        hashed_token = bcrypt.hash(token)
        revoked_token = RevokedToken(token_hash=hashed_token)
        db.session.add(revoked_token)
        db.session.commit()
        return jsonify({'message': 'Token revoked successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logging.exception(f"Error revoking token: {e}")
        return jsonify({'message': 'Internal server error'}), 500


@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")  # Limit to 5 registrations per minute per IP
def register():
    """
    Registers a new user.  Requires a 'username' in the request body.
    Generates a secure token for the user.
    """
    data = request.get_json()
    if not data or 'username' not in data:
        return jsonify({'message': 'Username is required'}), 400

    username = data['username']
    # Sanitize the username to prevent XSS
    username = bleach.clean(username)

    token = secrets.token_hex(60)  # Generate a strong, random token
    hashed_token = bcrypt.hash(token)  # Hash the token before storing

    try:
        new_user = User(username=username, token_hash=hashed_token)  # Store the hashed token
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully', 'token': token}), 201  # Return the original token
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Username already exists'}), 409
    except Exception as e:
        db.session.rollback()
        logging.exception(f"Error during registration: {e}")  # Log the full exception traceback
        return jsonify({'message': 'Internal server error'}), 500


# Schema for validating the numbers list
class NumbersSchema(Schema):
    numbers = fields.List(fields.Float(validate=lambda n: -1000 <= n <= 1000), required=True)  # Example range validation


@app.route('/median', methods=['POST'])
@limiter.limit("20 per minute")  # Limit to 20 median calculations per minute per IP
@token_required
def median_route():
    """
    Calculates the median of a list of numbers provided in the request body.
    Requires a valid user token for authentication.
    @return: A JSON object with a "message" key containing the median of the numbers.
    """

    data = request.get_json()
    if not data:
        return jsonify({'message': 'Request body is required'}), 400

    try:
        result = NumbersSchema().load(data)
        numbers = result['numbers']
    except ValidationError as err:
        return jsonify({'message': err.messages}), 400

    if not numbers:
        return jsonify({'message': 'Cannot calculate median of an empty list'}), 400

    try:
        median = statistics.median(numbers)
        return jsonify({'message': str(median)}), 200  # Return median as a string
    except statistics.StatisticsError as e:
        logging.error(f"Statistics error: {e}")
        return jsonify({'message': 'Error calculating median'}), 500
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        return jsonify({'message': 'Internal server error'}), 500


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # Enforce HTTPS
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'message': 'Rate limit exceeded. Please try again later.'}), 429


@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")  # Log the exception
    return jsonify({'message': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

