import secrets
import os
import bcrypt
from urllib.parse import urlparse, urljoin
from datetime import timedelta

from flask import Flask, session, abort, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_wtf.csrf import CSRFProtect
import logging

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_session import Session

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a secure random key for the session
app.secret_key = secrets.token_hex(32)  # Use a strong, random key

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')  # Use environment variable for database URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking for performance

# Session configuration
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = SQLAlchemy(app)  # Use the same SQLAlchemy instance
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout

db = SQLAlchemy(app)
Session(app)

# CSRF protection
csrf = CSRFProtect(app)

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["50 per minute"]
)

# Content Security Policy
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],
    'style-src': ['\'self\'', '\'unsafe-inline\''],
    'img-src': ['\'self\'', 'data:'],
}

# Security Headers and HTTPS enforcement
talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=True,  # Enforce HTTPS (if not already handled by the web server)
    frame_options='SAMEORIGIN',
    x_content_type_options='nosniff',
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True,
)


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    password = db.Column(db.String(128), nullable=False)  # Store hashed passwords

    def set_password(self, password):
        """Hashes the password using bcrypt and stores the hash."""
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Checks if the given password matches the stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


# Form classes for validation and CSRF protection
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Helper function to check if a URL is safe for redirection
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


@app.route('/register', methods=['POST', 'GET'])
@limiter.limit("5 per minute")
def register():
    """Registers a new user."""
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if User.query.filter_by(username=username).first():
            logging.warning(f"Registration attempt with existing username: {username}")
            error_message = "Registration failed." if os.environ.get('FLASK_ENV') == 'production' else "Username already exists"
            return render_template('register.html', form=form, error=error_message)

        user = User(username=username)
        user.set_password(password)  # Hash the password before storing
        db.session.add(user)
        db.session.commit()
        logging.info(f"New user registered: {username}")
        return redirect(url_for('login'))  # Redirect to login after registration

    return render_template('register.html', form=form)


@app.route('/login', methods=['POST', 'GET'])
@limiter.limit("5 per minute")
def login():
    """Logs in an existing user."""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        next_url = request.form.get('next')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):  # Check the hashed password
            session['username'] = username  # Store username in session
            session.permanent = True # Make the session permanent
            logging.info(f"User logged in: {username}")

            if next_url and is_safe_url(next_url):
                return redirect(next_url)
            else:
                logging.warning(f"Unsafe redirect attempted to: {next_url}")
                return redirect(url_for('home'))  # Redirect to a default page after login
        else:
            logging.warning(f"Failed login attempt for username: {username}")
            error_message = "Authentication failed." if os.environ.get('FLASK_ENV') == 'production' else "Authentication failed"
            return render_template('login.html', form=form, error=error_message)

    next_url = request.args.get('next')
    return render_template('login.html', form=form, next=next_url)


@app.route('/logout')
def logout():
    """Logs the user out by removing the username from the session."""
    username = session.pop('username', None)
    if username:
        logging.info(f"User logged out: {username}")
    return redirect(url_for('login'))


@app.route('/home')
def home():
    """A simple home page that requires login."""
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        return redirect(url_for('login'))


@app.route('/')
def index():
    return redirect(url_for('home'))


if __name__ == '__main__':
    # Ensure the database file exists
    with app.app_context():
        db.create_all()

    # Disable debug mode in production
    app.run(debug=False)

