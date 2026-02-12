import os
import bcrypt
from flask import Flask, render_template, request, session, redirect, url_for, escape, flash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import secrets  # For generating secure random values

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration settings
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(24)  # Use secrets for better randomness
if not app.config['SECRET_KEY']:
    logging.warning("SECRET_KEY not set. Using a temporary key. This is insecure in production.")

# Session Cookie Security
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Default, but explicit is good
app.config['SESSION_COOKIE_SECURE'] = True  # Only set to True when using HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Or 'Strict'

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="memory://"  # Use a persistent storage in production (e.g., redis://)
)

# In a real application, store user credentials (username, salt, hashed password)
# in a database.  This is a simplified in-memory example for demonstration.
users = {
    'testuser': {
        'hashed_password': bcrypt.hashpw('password'.encode('utf-8'), bcrypt.gensalt()), # Example hashed password
    }
}


# Form for login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20),
                                                   Regexp(r'^[a-zA-Z0-9_]+$',
                                                          message="Username must contain only letters, numbers, and underscores")])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Limit login attempts to 5 per minute
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username in users:
            user_data = users[username]
            hashed_password_from_db = user_data['hashed_password']

            if bcrypt.checkpw(password.encode('utf-8'), hashed_password_from_db):
                session['username'] = username
                logging.info(f"User {username} logged in successfully.")
                flash('Login successful!', 'success')  # Flash message
                return redirect(url_for('session_page'))
            else:
                logging.warning(f"Failed login attempt for user {username}.")
                flash('Incorrect username or password', 'error')  # Flash message
        else:
            logging.warning(f"Failed login attempt for unknown user {username}.")
            flash('Incorrect username or password', 'error')  # Flash message

    return render_template('login.html', form=form)


@app.route('/session')
def session_page():
    if 'username' in session:
        username = session['username']
        return render_template('session.html', username=escape(username))  # Still escaping, but consider Jinja2 autoescape
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    if 'username' in session:
        username = session['username']
        session.pop('username', None)
        logging.info(f"User {username} logged out.")
        flash('Logged out successfully!', 'info')  # Flash message
    return redirect(url_for('login'))


@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning("Rate limit exceeded.")
    flash("Rate limit exceeded. Please try again later.", 'warning')  # Flash message
    return render_template('error.html', message="Rate limit exceeded. Please try again later.", code=429), 429


@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")  # Log the full exception
    flash("An error occurred. Please try again later.", 'error')  # Flash message
    return render_template('error.html', message="An error occurred. Please try again later.", code=500), 500


if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc") # Enable HTTPS with a self-signed certificate for testing

