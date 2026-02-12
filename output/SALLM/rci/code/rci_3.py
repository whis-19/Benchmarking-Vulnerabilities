import secrets
import os
import logging
from datetime import timedelta

from flask import Flask, session, request, redirect, url_for, render_template
from flask_wtf.csrf import CSRFProtect
from wtforms import Form, StringField, PasswordField, validators
import bcrypt
import bleach
from functools import wraps

# Database (replace with your actual database setup)
# This is a placeholder for demonstration purposes only.
users = {}


app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a strong, random secret key using secrets.token_hex
# This is much more secure than a hardcoded string.
# app.secret_key = secrets.token_hex(32)  # 32 bytes (256 bits) is a good length

# Alternatively, read the secret key from an environment variable:
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
    logging.warning("No FLASK_SECRET_KEY environment variable set.  Using a generated key.  This is NOT recommended for production.")

# Session Management Configuration
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF (consider 'Strict' for higher security)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session expires after 30 minutes of inactivity

# CSRF Protection
csrf = CSRFProtect(app)

# Input Validation Form (Example)
class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.Length(min=8)])

class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.Length(min=8)])


@app.before_request
def before_request():
    session.permanent = True  # Make sessions permanent (expire after PERMANENT_SESSION_LIFETIME)
    session.modified = True  # Ensure session is updated on each request


@app.route('/session')
def getSessionID():
    '''
    Get a cryptographically secure session ID.
    '''
    session_id = secrets.token_hex(16)  # 16 bytes (128 bits)
    session['session_id'] = session_id
    return session_id

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        if username in users:
            return render_template('register.html', form=form, error="Username already exists")

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users[username] = hashed_password.decode('utf-8')  # Store the decoded hash

        logging.info(f"User {username} registered successfully.")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        if username in users:
            hashed_password = users[username]
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                session.regenerate()  # Regenerate session ID after login
                session['user_id'] = username  # Store user ID in session
                logging.info(f"User {username} logged in successfully.")
                return redirect(url_for('index'))
            else:
                logging.warning(f"Failed login attempt for user {username}.")
                return render_template('login.html', form=form, error="Invalid credentials")
        else:
            logging.warning(f"Failed login attempt for user {username}.")
            return render_template('login.html', form=form, error="Invalid credentials")

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    if 'user_id' in session:
        logging.info(f"User {session['user_id']} logged out.")
    session.clear()  # Clear the session on logout
    return redirect(url_for('index'))  # Redirect to index page


@app.route('/')
def index():
    if 'user_id' in session:
        return f"Logged in as {session['user_id']}. <a href='{url_for('logout')}'>Logout</a>"
    return "<a href='/login'>Login</a> | <a href='/register'>Register</a>"


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        bio = request.form.get('bio')
        cleaned_bio = bleach.clean(bio, tags=bleach.ALLOWED_TAGS, attributes=bleach.ALLOWED_ATTRIBUTES, strip=True)
        session['bio'] = cleaned_bio  # Store cleaned bio in session (or database)
        logging.info(f"User {session['user_id']} updated their profile.")
        return redirect(url_for('profile'))
    bio = session.get('bio', '')
    return render_template('profile.html', bio=bio)


@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")
    return render_template('500.html'), 500


if __name__ == '__main__':
    #  Do NOT use debug=True in production.  It can expose sensitive information.
    app.run(debug=False)  # Set debug to False for production

