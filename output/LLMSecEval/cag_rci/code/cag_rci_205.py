from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
from wtforms import Form, StringField, PasswordField, HiddenField, validators
from wtforms.validators import InputRequired, Length, ValidationError
import os
import secrets  # For generating cryptographically secure random numbers
import logging
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Replace with a strong, persistent secret key
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SECURE'] = True  # Only send session cookie over HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # Session timeout
bcrypt = Bcrypt(app)
limiter = Limiter(app, key_func=get_remote_address)

# Example database (replace with a real database like PostgreSQL)
users = {}  # Insecure!  Use a database!

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_csrf_token():
    return secrets.token_urlsafe(16)  # Use secrets module for strong randomness

class LoginForm(Form):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[InputRequired()])
    csrf_token = HiddenField('CSRF Token', validators=[InputRequired()])

    def validate_csrf_token(form, field):
        if field.data != session.get('csrf_token'):
            raise ValidationError('Invalid CSRF token')


@app.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    flash("Too many login attempts. Please try again later.", 'error')
    return render_template('login.html', form=LoginForm()), 429


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    """Login page."""
    if request.method == 'POST':
        form = LoginForm(request.form)
        if form.validate():
            username = form.username.data
            password = form.password.data

            if username in users and bcrypt.check_password_hash(users[username], password):
                # Authentication successful
                session['username'] = username
                session.regenerate()  # Prevent session fixation
                session.permanent = True # Enable session timeout
                logging.info(f"User {username} logged in successfully from {request.remote_addr}")
                return redirect(url_for('secret'))
            else:
                flash("Invalid credentials.", 'error')  # Generic error message
                logging.warning(f"Failed login attempt for user {username} from {request.remote_addr}")
                return render_template('login.html', form=form)  # Pass the form back to the template
        else:
            logging.warning(f"Invalid form submission from {request.remote_addr}: {form.errors}")
            return render_template('login.html', form=form)

    # GET request: Generate CSRF token and render the form
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    form = LoginForm(csrf_token=csrf_token)  # Pass CSRF token to the form
    return render_template('login.html', form=form) # Pass the form to the template


@app.route('/secret')
def secret():
    if 'username' in session:
        return f"Secret area for {session['username']}"
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc") # Use HTTPS in production!

