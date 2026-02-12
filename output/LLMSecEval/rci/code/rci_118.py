import hashlib
import os
from flask import Flask, request, render_template, session, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random secret key for session management
csrf = CSRFProtect(app)

# Configure session cookie security
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF (Lax or Strict)

# Configure logging
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')


# In a real application, store usernames and hashed passwords securely in a database.
# NEVER store passwords in plain text.
# This is a simplified example for demonstration purposes only.
# Using werkzeug.security for password hashing
users = {
    "admin": {
        "hashed_password": generate_password_hash("password"),
        "role": "admin"
    },
    "user1": {
        "hashed_password": generate_password_hash("secure_password"),
        "role": "user"
    }
}


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username in users and check_password_hash(users[username]["hashed_password"], password):
            session['username'] = username  # Store username in session
            return redirect(url_for('protected'))  # Redirect to a protected page
        else:
            logging.warning(f"Failed login attempt for user: {username}")
            return render_template('login.html', form=form, error="Invalid credentials")

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


# Removed check_mod and check_mod_route as they are unnecessary and dangerous.

@app.route('/form')
def form():
    """Renders a simple form for testing."""
    return "This route is no longer used."


if __name__ == '__main__':
    app.run(debug=False, ssl_context='adhoc') # Disable debug mode and enable HTTPS

