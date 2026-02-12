import secrets
import hashlib
import os
import logging

from flask import Flask, request, jsonify, session, redirect, url_for, abort, render_template
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from bleach import clean
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
from flask_talisman import Talisman
# from flask_cors import CORS # Import if you need CORS

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Security Configurations
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Recommended for better security
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust as needed
    storage_uri="memory://"  # Use a persistent store like Redis for production
)

# Initialize CSRF protection
csrf = CSRFProtect(app)
csrf.init_app(app)

db = SQLAlchemy(app)

# Talisman for security headers
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': '\'self\'', # Add CDNs if needed, with SRI
        'style-src': '\'self\'', # Add CDNs if needed, with SRI
        'img-src': '\'self\' data:',
        'font-src': '\'self\'',
    },
    force_https=False, # Set to True in production
    session_cookie_secure=True, # Redundant, but explicit
    session_cookie_http_only=True, # Redundant, but explicit
    session_cookie_samesite='Lax', # Redundant, but explicit
    frame_options='DENY',
)

# CORS(app) # Initialize if you need CORS

# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        """Hashes the password using pbkdf2_hmac."""
        # Generate a random salt
        salt = os.urandom(16)
        self.password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        ).hex() + salt.hex() # Store hash + salt

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        # Extract the salt from the stored hash
        stored_hash = self.password_hash
        salt = bytes.fromhex(stored_hash[-32:])
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        ).hex()
        return hashed_password == stored_hash[:-32]


# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)]) # Add password complexity
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


def login_required(f):
    """Decorator to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit registration attempts
def register():
    """Registers a new user."""
    form = RegistrationForm()
    if form.validate_on_submit():
        username = clean(form.username.data)  # Sanitize username
        password = form.password.data

        if User.query.filter_by(username=username).first():
            logging.warning(f"Registration attempt with existing username: {username}")
            return jsonify({'message': 'Username already exists'}), 409

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        try:
            db.session.commit()
            logging.info(f"User registered successfully: {username}")
            return jsonify({'message': 'User registered successfully'}), 201
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error registering user: {e}")
            return jsonify({'message': 'An error occurred during registration'}), 500
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    """Logs in an existing user."""
    form = LoginForm()
    if form.validate_on_submit():
        username = clean(form.username.data)  # Sanitize username
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            logging.warning(f"Failed login attempt for username: {username}")
            return jsonify({'message': 'Invalid username or password'}), 401

        session['username'] = username
        logging.info(f"User logged in successfully: {username}")
        return jsonify({'message': 'Login successful'}), 200
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    username = session.get('username')
    session.pop('username', None)
    logging.info(f"User logged out: {username}")
    return jsonify({'message': 'Logout successful'}), 200


@app.route('/median', methods=['POST'])
@login_required
def avg():
    """
    Get the "numbers" query parameter and return the median of the numbers.
    @return: A JSON object with a "message" key containing the average of the numbers.
    """
    try:
        numbers_str = request.args.get('numbers')
        if not numbers_str:
            logging.warning("Missing 'numbers' parameter")
            return jsonify({'message': 'Missing "numbers" parameter'}), 400

        numbers = [float(x) for x in numbers_str.split(',')]
        if not numbers:
            logging.warning("No numbers provided")
            return jsonify({'message': 'No numbers provided'}), 400

        numbers.sort()
        n = len(numbers)
        if n % 2 == 0:
            median = (numbers[n // 2 - 1] + numbers[n // 2]) / 2
        else:
            median = numbers[n // 2]

        return jsonify({'message': median}), 200

    except ValueError:
        logging.warning("Invalid number format")
        return jsonify({'message': 'Invalid number format'}), 400
    except Exception as e:
        logging.exception("Error processing request")  # Log the full exception
        return jsonify({'message': 'An error occurred'}), 500


@app.errorhandler(404)
def not_found(error):
    """Handles 404 errors."""
    logging.warning(f"Resource not found: {request.path}")
    return jsonify({'message': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_server_error(error):
    """Handles 500 errors."""
    logging.error(f"Internal server error: {error}")
    return jsonify({'message': 'Internal server error'}), 500


@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = jsonify({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, ssl_context='adhoc')

