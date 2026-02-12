import os
from flask import Flask, request, render_template, session, redirect, url_for
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Length
import bcrypt
from html import escape
import logging
import re  # For password complexity

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set a strong secret key for the app
app.config['SECRET_KEY'] = os.urandom(24)
csrf = CSRFProtect(app)  # Enable CSRF protection

# Session Security
app.config['SESSION_COOKIE_SECURE'] = True  # Only transmit over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

# In a real application, store usernames and hashed passwords securely in a database.
# NEVER store passwords in plain text.
# This is a simplified example for demonstration purposes only.
users = {
    "admin": {
        "hashed_password": bcrypt.hashpw("Password123!".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        "role": "admin"
    },
    "user1": {
        "hashed_password": bcrypt.hashpw("SecurePass@word".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        "role": "user"
    }
}


def password_complexity(form, field):
    """Validates password complexity."""
    password = field.data
    if not re.search(r"[a-z]", password):
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValidationError("Password must contain at least one number.")
    if not re.search(r"[@$!%*#?&]", password):
        raise ValidationError("Password must contain at least one special character (@$!%*#?&).")


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8), password_complexity])
    submit = SubmitField('Login')


def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string


def verify_password(entered_password, stored_hash):
    """Verifies the entered password against the stored hash using bcrypt."""
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_hash.encode('utf-8'))


def sanitize_input(input_string):
    """Sanitizes user input to prevent XSS."""
    return escape(input_string)


def check_mod(username, password):
    """
    Checks if the username and password are correct.

    Args:
        username (str): The username entered by the user.
        password (str): The password entered by the user.

    Returns:
        bool: True if the username and password are correct, False otherwise.
    """
    if username in users:
        stored_hash = users[username]["hashed_password"]
        if verify_password(password, stored_hash):
            logging.info(f"User {username} logged in successfully.")
            return True
        else:
            logging.warning(f"Failed login attempt for user {username} - incorrect password.")
            return False
    else:
        logging.warning(f"Failed login attempt for user {username} - user not found.")
        return False


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Sanitize the input
        username = sanitize_input(username)
        password = sanitize_input(password)

        if check_mod(username, password):
            session['username'] = username
            return redirect(url_for('protected'))
        else:
            return render_template('login.html', form=form, error="Login failed.")  # More generic error

    return render_template('login.html', form=form, error=None)


@app.route('/protected')
def protected():
    if 'username' in session:
        return f"Logged in as {session['username']}.  <a href='/logout'>Logout</a>"
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


# Removed check_mod_route and form route as per the critique's recommendation.

if __name__ == '__main__':
    #  NEVER TRUE IN PRODUCTION
    #  Use a production WSGI server like gunicorn or uWSGI
    app.run(debug=True)

