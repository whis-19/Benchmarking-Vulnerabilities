import os
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp
import bcrypt
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis  # Import Redis library

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(16)
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('CSRF_SECRET_KEY') or secrets.token_hex(16)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
# Choose between Redis and Memcached for production. Redis offers persistence.
# Example using Redis:
redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379')  # Get Redis URL from environment
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=redis_url,  # Use Redis for storage
    strategy="fixed-window",
)

# Database setup (using SQLite for simplicity - consider PostgreSQL for production)
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()


def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)) # Explicit cost factor
    return hashed_password.decode('utf-8')  # Store as string

def verify_password(stored_password, provided_password):
    """Verifies the provided password against the stored bcrypt hash."""
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))


def create_user(email, password):
    """Creates a new user in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)",
                       (email, hashed_password))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError as e:
        logging.error(f"Error creating user: {e}")
        conn.close()
        return None  # Email already exists


def get_user_by_email(email):
    """Retrieves a user from the database by email."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user


def update_user_email(user_id, new_email):
    """Updates a user's email in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError as e:
        logging.error(f"Error updating user email: {e}")
        conn.close()
        return False  # Email already exists


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8),
                                       Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                                              message="Password must contain at least 8 characters, including one uppercase letter, one lowercase letter, one number, and one special character.")])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ChangeEmailForm(FlaskForm):
    old_email = StringField('Old Email', validators=[DataRequired(), Email()])
    new_email = StringField('New Email', validators=[DataRequired(), Email()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Change Email')

@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html', email=session['email'])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit registration
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user_id = create_user(email, password)
        if user_id:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email already exists.', 'error')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = get_user_by_email(email)

        if user and verify_password(user['password'], password):
            session['user_id'] = user['id']
            session['email'] = user['email']
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('email', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if 'user_id' not in session:
        flash('You must be logged in to change your email.', 'warning')
        return redirect(url_for('login'))

    form = ChangeEmailForm()
    if form.validate_on_submit():
        old_email = form.old_email.data
        new_email = form.new_email.data
        confirm_password = form.confirm_password.data

        if old_email != session['email']:
            flash('Incorrect old email.', 'error')
            return render_template('change_email.html', form=form)

        user = get_user_by_email(old_email)
        if not user:
            flash('User not found.', 'error')  # This should not happen if session is valid
            return render_template('change_email.html', form=form)

        if not verify_password(user['password'], confirm_password):
            flash('Incorrect password.', 'error')
            return render_template('change_email.html', form=form)

        if update_user_email(session['user_id'], new_email):
            session['email'] = new_email  # Update the session
            flash('Email changed successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('New email already exists.', 'error')
    return render_template('change_email.html', form=form)

# Example of setting a CSP header (can be done in the web server configuration as well)
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    return response

if __name__ == '__main__':
    app.run(debug=True)

