import secrets
import hashlib

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc  # Import SQLAlchemy exceptions

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
db = SQLAlchemy(app)


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    token_hash = db.Column(db.String(128), nullable=False)  # Store token hash


def hash_token(token):
    """Hashes the token using SHA-512."""
    return hashlib.sha512(token.encode('utf-8')).hexdigest()


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not isinstance(data, dict):
        return jsonify({"message": "Invalid request body"}), 400

    username = data.get("username", "")
    if not username or not isinstance(username, str) or len(username) > 80:
        return jsonify({"message": "Invalid username"}), 400

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
        return jsonify({"message": "Invalid request body"}), 400

    username = data.get("username", "")
    token = data.get("token", "")

    if not username or not isinstance(username, str) or len(username) > 80:
        return jsonify({"message": "Invalid username"}), 400
    if not token or not isinstance(token, str):
        return jsonify({"message": "Invalid token"}), 400

    user = User.query.filter_by(username=username).first()

    if user:
        hashed_token = hash_token(token)
        if user.token_hash == hashed_token:
            return jsonify({"message": "Authorized"}), 200
        else:
            return jsonify({"message": "Unauthorized"}), 401
    else:
        return jsonify({"message": "Unauthorized"}), 401


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables within the app context
    app.run(debug=True, ssl_context='adhoc') # Enable HTTPS with a self-signed certificate for testing

