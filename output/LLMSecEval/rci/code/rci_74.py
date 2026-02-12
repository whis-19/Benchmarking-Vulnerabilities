from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
import os
import secrets
import bcrypt  # pip install bcrypt
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email
from datetime import timedelta
from flask_session import Session
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a secure random key for the session
# Store the secret key in an environment variable or a secure configuration file.
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# Session configuration
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_TYPE'] = 'filesystem'  # Or 'redis', 'memcached', 'mongodb'
app.config['SESSION_FILE_DIR'] = 'flask_session'  # Create this directory
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # or 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session expires after 30 minutes of inactivity

Session(app)

# CSRF protection
csrf = CSRFProtect(app)

# In a real application, you would store user credentials securely in a database.
# This is a simplified example for demonstration purposes only.
ADMIN_USERNAME = "admin"
# Store the password securely using bcrypt
ADMIN_PASSWORD = "admin".encode('utf-8')
ADMIN_PASSWORD_HASH = bcrypt.hashpw(ADMIN_PASSWORD, bcrypt.gensalt())  # Generate a salt and hash

# Function to verify password (replace with a proper database lookup and password verification)
def verify_password(username, password):
    if username == ADMIN_USERNAME:
        return bcrypt.checkpw(password.encode('utf-8'), ADMIN_PASSWORD_HASH)
    return False

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers a new user."""
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # In a real application, you would:
        # 1. Check if the username or email already exists in the database.
        # 2. Hash the password using bcrypt.
        # 3. Store the username, email, and password hash in the database.

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Displays the login form.
    """
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if verify_password(username, password):
            session['logged_in'] = True
            session['username'] = username # Store username in session
            logging.info(f"User {username} logged in from {request.remote_addr}")
            return redirect(url_for('admin_page'))
        else:
            flash('Invalid username or password', 'error')  # Use flash messages with category
            logging.warning(f"Failed login attempt for user {username} from {request.remote_addr}")
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)  # Create a login.html template

@app.route('/admin')
def admin_page():
    """
    Displays the admin page.  Requires the user to be logged in.
    """
    if not session.get('logged_in'):
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    username = session.get('username')
    return render_template('admin.html', username=username)  # Create an admin.html template

@app.route('/logout')
def logout():
    """
    Logs the user out by clearing the session.
    """
    username = session.get('username')
    if username:
        logging.info(f"User {username} logged out from {request.remote_addr}")
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    """
    Handles 403 Forbidden errors.
    """
    logging.warning(f"403 Forbidden error: {e} - User IP: {request.remote_addr} - URL: {request.url}")
    return render_template('403.html'), 403 # Create a 403.html template

@app.errorhandler(404)
def page_not_found(e):
    """Handles 404 Page Not Found Error"""
    logging.warning(f"404 Page Not Found error: {e} - User IP: {request.remote_addr} - URL: {request.url}")
    return render_template('404.html'), 404 # Create a 404.html template

@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 Internal Server Error"""
    # Log the error for debugging purposes (in a real application, use a proper logging system)
    app.logger.error(f"Internal Server Error: {e} - User IP: {request.remote_addr} - URL: {request.url}")
    return render_template('500.html'), 500 # Create a 500.html template

if __name__ == '__main__':
    # NEVER use debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

