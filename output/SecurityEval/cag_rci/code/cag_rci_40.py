import bcrypt
import os
import secrets
import time
from functools import wraps
from flask import Flask, request, session, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session  # Import Flask-Session
import redis  # Import Redis client

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure session security
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Configure Flask-Session for Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'session:'
Session(app)


# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Replace with your actual settings
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

with app.app_context():
    db.create_all()


# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'user_agent' not in session:
            return jsonify({'message': 'Authentication required'}), 401

        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'message': 'Authentication required'}), 401

        if session['user_agent'] != request.headers.get('User-Agent'):
            return jsonify({'message': 'Authentication required'}), 401

        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['POST'])
@limiter.limit("5/minute")
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):  # Corrected bcrypt.checkpw
        session['user_id'] = user.id
        session['username'] = username
        session['user_agent'] = request.headers.get('User-Agent')
        return jsonify({'message': 'Login successful'}), 200
    else:
        time.sleep(0.2)
        return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()  # Clear all session data
    return jsonify({'message': 'Logout successful'}), 200


@app.route('/protected', methods=['GET'])
@login_required
def protected():
    return jsonify({'message': f'Hello, {session["username"]}! This is a protected resource.'}), 200


def checkAdminPassword(password):
    admin_user = User.query.filter_by(username="admin").first()
    if not admin_user:
        return False

    return bcrypt.checkpw(password.encode('utf-8'), admin_user.password_hash)  # Corrected bcrypt.checkpw


if __name__ == '__main__':
    # REMOVE ALL ADMIN PASSWORD INITIALIZATION CODE FROM HERE.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

