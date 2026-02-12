import os
import secrets
from urllib.parse import urlparse

from flask import Flask, render_template, request, redirect, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps

# Database (replace with your actual database setup)
# For demonstration, using a simple dictionary
users = {
    "admin": "P@$$wOrd123!"
}


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(24)

    # Session Cookie Configuration
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent client-side JavaScript access
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF (Lax or Strict)

    # Rate Limiting
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["5 per minute"]  # Example: Allow 5 requests per minute
    )

    # HTTPS Enforcement
    @app.before_request
    def before_request():
        """Redirect HTTP to HTTPS."""
        if not request.is_secure and app.env != "development":  # Don't redirect in development
            url = request.url
            parsed_url = urlparse(url)
            url = parsed_url._replace(scheme="https").geturl()
            return redirect(url, code=301)

    # Password Complexity Validator
    def password_complexity(form, field):
        if not any(char.isdigit() for char in field.data):
            raise ValidationError('Password must contain at least one digit.')
        if not any(char.isupper() for char in field.data):
            raise ValidationError('Password must contain at least one uppercase letter.')
        if not any(char.islower() for char in field.data):
            raise ValidationError('Password must contain at least one lowercase letter.')
        if not any(char in "!@#$%^&*()" for char in field.data):
            raise ValidationError('Password must contain at least one special character.')

    # Login Form with Input Validation
    class LoginForm(FlaskForm):
        username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25), Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only alphanumeric characters and underscores")])
        password = PasswordField('Password', validators=[DataRequired(), Length(min=8), password_complexity])
        submit = SubmitField('Login')

    # Authentication Decorator
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect('/login')
            return f(*args, **kwargs)
        return decorated_function

    # Routes
    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")  # Apply rate limiting to the login route
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            if username in users and users[username] == password:
                session['username'] = username
                flash('Login successful!', 'success')
                app.logger.info(f"User {username} logged in successfully") # Logging successful login
                return redirect('/')
            else:
                flash('Invalid username or password', 'danger')
                app.logger.warning(f"Failed login attempt for user {username}") # Logging failed login
        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        username = session.get('username')
        session.pop('username', None)
        flash('Logged out successfully!', 'info')
        app.logger.info(f"User {username} logged out successfully") # Logging logout
        return redirect('/login')

    @app.route('/')
    @login_required
    def home():
        username = session['username']
        return render_template('home.html', username=username)

    # Example HTML Templates (create these in a 'templates' folder)
    # login.html:
    #

