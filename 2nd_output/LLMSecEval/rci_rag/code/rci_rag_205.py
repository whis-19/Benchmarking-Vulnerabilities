import os
import hashlib
from flask import Flask, render_template, request, session, redirect, url_for, abort, flash
from functools import wraps
import secrets
import logging
import bcrypt  # Import bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import sqlite3

# Database setup
DATABASE_FILE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Flask app setup
app = Flask(__name__)

# Securely manage the secret key (environment variable)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(24)

# Talisman setup for security headers (HTTPS is assumed to be handled by the web server)
talisman = Talisman(app,
                    content_security_policy={
                        'default-src': '\'self\'',
                        'script-src': '\'self\'',
                        'style-src': '\'self\'',
                        'img-src': '\'self\' data:',
                        'font-src': '\'self\'',
                        'object-src': '\'none\'',
                    },
                    force_https=False,  # Set to True in production if Flask handles HTTPS
                    session_cookie_secure=True,
                    session_cookie_httponly=True,
                    session_cookie_samesite='Lax')

# Rate limiting setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # Use a more persistent storage in production (e.g., Redis)
)

# Configure logging (important for security audits, but avoid logging sensitive data)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# CSRF protection using Flask-WTF
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=100)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Hashing function (use a strong hashing algorithm like bcrypt or scrypt in production)
def hash_password(password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to view this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_hash = user['password']
            if check_password(password, stored_hash):
                session['username'] = username
                logging.info(f"User {username} logged in successfully.") # Log successful login
                return redirect(url_for('secret'))
            else:
                flash('Invalid username or password.')
                logging.warning(f"Failed login attempt for user {username}.") # Log failed login attempt (without password)
        else:
            flash('Invalid username or password.')
            logging.warning(f"Failed login attempt for user {username}.") # Log failed login attempt (without password)

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit registration attempts
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            hashed_password = hash_password(password)
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            logging.info(f"New user {username} registered.")
            flash("Registration successful. Please log in.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
        finally:
            conn.close()

    return render_template('register.html', form=form)


@app.route('/secret')
@login_required
def secret():
    # Access control enforced by the login_required decorator
    # Only authenticated users can access this page
    return render_template('secret.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    session.pop('username', None)
    logging.info(f"User {username} logged out.") # Log logout
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

if __name__ == '__main__':
    init_db()  # Initialize the database
    # Never run in debug mode in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

