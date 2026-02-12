import os
import hashlib
import secrets
import configparser
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.fernet import Fernet
import logging
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_wtf.csrf import CSRFProtect
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bleach import clean
from bcrypt import hashpw, gensalt, checkpw  # Use bcrypt for password hashing

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key
csrf = CSRFProtect(app)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["20 per minute"]  # Adjust as needed
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration file path
CONFIG_FILE = os.environ.get('CONFIG_FILE', 'config.ini')  # Use environment variable if available

# Password complexity requirements
PASSWORD_MIN_LENGTH = 8
PASSWORD_UPPERCASE = 1
PASSWORD_LOWERCASE = 1
PASSWORD_NUMBERS = 1
PASSWORD_SPECIAL = 1

# Encryption key (generated once and stored securely)
def generate_encryption_key():
    """Generates a Fernet encryption key."""
    key = Fernet.generate_key()
    return key.decode()

def load_config():
    """Loads configuration from config.ini, creating it if it doesn't exist."""
    config = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        # First-time setup: generate encryption key and store it securely
        encryption_key = generate_encryption_key()
        config['security'] = {'encryption_key': encryption_key}
        config['users'] = {}  # Empty user section initially
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
        print("Configuration file created.  Please add an initial user via the registration page.") # Inform user
        os.chmod(CONFIG_FILE, 0o600)  # Restrict file permissions
    else:
        config.read(CONFIG_FILE)
    return config

config = load_config()

def save_config(config):
    """Saves the configuration to config.ini."""
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)
    os.chmod(CONFIG_FILE, 0o600)  # Restrict file permissions after saving

def get_fernet():
    """Returns a Fernet instance using the encryption key from the config."""
    encryption_key = config['security']['encryption_key'].encode()
    return Fernet(encryption_key)

def encrypt_data(data):
    """Encrypts data using Fernet."""
    fernet = get_fernet()
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(data):
    """Decrypts data using Fernet."""
    fernet = get_fernet()
    decrypted_data = fernet.decrypt(data.encode()).decode()
    return decrypted_data

def hash_password(password):
    """Hashes the password using bcrypt."""
    salt = gensalt()  # Generate a random salt
    hashed_password = hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def verify_password(stored_hash, password):
    """Verifies the password against the stored hash using bcrypt."""
    return checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

# Custom password validator
def validate_password_complexity(form, field):
    password = field.data
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValidationError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long.")
    if PASSWORD_UPPERCASE and not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if PASSWORD_LOWERCASE and not re.search(r"[a-z]", password):
        raise ValidationError("Password must contain at least one lowercase letter.")
    if PASSWORD_NUMBERS and not re.search(r"[0-9]", password):
        raise ValidationError("Password must contain at least one number.")
    if PASSWORD_SPECIAL and not re.search(r"[^a-zA-Z0-9\s]", password):
        raise ValidationError("Password must contain at least one special character.")

# Forms using Flask-WTF
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), validate_password_complexity])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        if username.data in config['users']:
            raise ValidationError('That username is already taken.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ChangeEmailForm(FlaskForm):
    old_email = StringField('Old Email', validators=[DataRequired(), Email()])
    new_email = StringField('New Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Change Email')

    def validate_new_email(self, new_email):
        if new_email.data == self.old_email.data:
            raise ValidationError('New email must be different from the old email.')


@app.route('/')
def index():
    return render_template('index.html', username=session.get('username'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit registration
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data

        # Sanitize inputs (example using bleach)
        username = clean(username)
        email = clean(email)

        password_hash = hash_password(password)
        encrypted_email = encrypt_data(email)

        config['users'][username] = f"{password_hash}:{encrypted_email}"
        save_config(config)

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Sanitize username
        username = clean(username)

        if username in config['users']:
            user_data = config['users'][username].split(':')
            password_hash = user_data[0]

            if verify_password(password_hash, password):
                session['username'] = username
                session.permanent = True  # Make session permanent
                app.permanent_session_lifetime = 3600  # Session expires after 1 hour (adjust as needed)
                flash('Login successful!', 'success')
                logging.info(f"User {username} logged in successfully.")
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password.', 'error') # Less specific error
                logging.warning(f"Failed login attempt for user {username} (incorrect password).")
        else:
            flash('Invalid username or password.', 'error') # Less specific error
            logging.warning(f"Failed login attempt for user {username} (username not found).")

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    username = session.get('username')
    if username:
        logging.info(f"User {username} logged out.")
    session.pop('username', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if 'username' not in session:
        flash('You must be logged in to change your email.', 'error')
        return redirect(url_for('login'))

    username = session['username']
    form = ChangeEmailForm()

    if form.validate_on_submit():
        old_email = form.old_email.data
        new_email = form.new_email.data
        password = form.password.data

        # Sanitize emails
        old_email = clean(old_email)
        new_email = clean(new_email)

        user_data = config['users'][username].split(':')
        password_hash = user_data[0]
        encrypted_email = user_data[1]
        decrypted_email = decrypt_data(encrypted_email)

        if not verify_password(password_hash, password):
            flash('Incorrect password.', 'error')
            return render_template('change_email.html', form=form)

        if old_email != decrypted_email:
            flash('Incorrect old email.', 'error')
            return render_template('change_email.html', form=form)


        encrypted_new_email = encrypt_data(new_email)
        config['users'][username] = f"{password_hash}:{encrypted_new_email}"
        save_config(config)

        flash('Email changed successfully!', 'success')
        logging.info(f"User {username} changed email successfully.")
        return redirect(url_for('index'))

    return render_template('change_email.html', form=form)

@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Too many requests. Please try again later.", "error")
    return render_template("login.html", form=LoginForm()), 429

if __name__ == '__main__':
    # Enable HTTPS for local testing (remove in production and use a proper SSL certificate)
    app.run(debug=True, host="0.0.0.0", ssl_context='adhoc')

