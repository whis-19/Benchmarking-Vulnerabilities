import hashlib
import secrets
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template, g, flash
import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
import bcrypt
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a strong, random secret key
app.jinja_env.autoescape = True  # Enable autoescaping

# Session cookie configuration
app.config['SESSION_COOKIE_SECURE'] = True  # Only transmit over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Recommended for better security

DATABASE = 'users.db'
LOGIN_ATTEMPTS_LIMIT = 5
LOCKOUT_DURATION = 60  # seconds

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["50 per minute"]  # Adjust as needed
)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def verify_password(password, hashed_password):
    """Verifies the password against the stored hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email(message='Invalid email address')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        db = get_db()
        with get_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE email = ?", (email.data,))
                if cur.fetchone():
                    raise ValidationError('Email address is already in use.')

    def validate_username(self, username):
        db = get_db()
        with get_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE username = ?", (username.data,))
                if cur.fetchone():
                    raise ValidationError('Username is already taken.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        hashed_password = hash_password(password)

        db = get_db()
        try:
            with get_db() as db:
                with db.cursor() as cur:
                    cur.execute("INSERT INTO users (username, email, password, email_verified) VALUES (?, ?, ?, ?)",
                                (username, email, hashed_password, False))
                    db.commit()

                    # Email Verification (Simplified - replace with actual email sending)
                    # In a real application, you'd generate a unique token, store it, and send it in an email.
                    logging.info(f"Simulating email verification for {email}.  Check your console.")
                    # For now, automatically verify the email
                    cur.execute("UPDATE users SET email_verified = ? WHERE email = ?", (True, email))
                    db.commit()

                    flash('Registration successful! Please log in.', 'success')
                    return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            db.rollback()
            form.errors['database'] = ['Email address or username already in use.']
            logging.error(f"Database IntegrityError: {e}")
            flash('Registration failed. Please try again.', 'error')
        except sqlite3.Error as e:
            db.rollback()
            form.errors['database'] = ['An unexpected error occurred. Please try again later.']
            logging.error(f"Database error: {e}")
            flash('Registration failed. Please try again.', 'error')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        db = get_db()
        try:
            with get_db() as db:
                with db.cursor() as cur:
                    cur.execute("SELECT id, username, password, login_attempts, locked_until, email_verified FROM users WHERE username = ?", (username,))
                    user = cur.fetchone()

                if user:
                    if user['locked_until'] and user['locked_until'] > time.time():
                        lockout_remaining = int(user['locked_until'] - time.time())
                        flash(f'Account locked. Try again in {lockout_remaining} seconds.', 'error')
                        return render_template('login.html', form=form)

                    hashed_password = user['password']
                    if verify_password(password, hashed_password):
                        if not user['email_verified']:
                            flash('Please verify your email address before logging in.', 'warning')
                            return render_template('login.html', form=form)

                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        session.regenerate()  # Regenerate session ID
                        logging.info(f"User {username} logged in successfully.")

                        # Reset login attempts on successful login
                        with db.cursor() as cur:
                            cur.execute("UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = ?", (user['id'],))
                            db.commit()

                        return redirect(url_for('index'))
                    else:
                        # Increment login attempts
                        new_attempts = user['login_attempts'] + 1
                        lockout_time = None
                        if new_attempts >= LOGIN_ATTEMPTS_LIMIT:
                            lockout_time = time.time() + LOCKOUT_DURATION
                            error_message = f'Account locked due to too many failed attempts. Try again in {LOCKOUT_DURATION} seconds.'
                            logging.warning(f"Account locked for user {username} due to too many failed login attempts.")
                        else:
                            error_message = 'Incorrect password.'
                            logging.warning(f"Failed login attempt for user {username}.")

                        with db.cursor() as cur:
                            cur.execute("UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?", (new_attempts, lockout_time, user['id']))
                            db.commit()

                        flash(error_message, 'error')
                        return render_template('login.html', form=form)
                else:
                    flash('Incorrect username.', 'error')
                    return render_template('login.html', form=form)
        except sqlite3.Error as e:
            logging.error(f"Database error during login: {e}")
            flash('An unexpected error occurred. Please try again later.', 'error')
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    logging.info("User logged out.")
    return redirect(url_for('login'))

@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_email = request.form['old_email']
        new_email = request.form['new_email']
        password = request.form['password']

        if not old_email or not new_email or not password:
            flash('All fields are required.', 'error')
            return render_template('change_email.html')

        if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
            flash('Invalid email format.', 'error')
            return render_template('change_email.html')

        user_id = session['user_id']

        try:
            with get_db() as db:
                with db.cursor() as cur:
                    # Verify old email and password
                    cur.execute("SELECT email, password FROM users WHERE id = ?", (user_id,))
                    user = cur.fetchone()

                    if not user:
                        flash('User not found.', 'error')
                        return render_template('change_email.html')

                    stored_email = user['email']
                    hashed_password = user['password']

                    if old_email != stored_email:
                        flash('Incorrect old email.', 'error')
                        return render_template('change_email.html')

                    if not verify_password(password, hashed_password):
                        flash('Incorrect password.', 'error')
                        return render_template('change_email.html')

                    # Double-Check Ownership:
                    cur.execute("SELECT id FROM users WHERE id = ? AND email = ?", (user_id, old_email))
                    ownership_check = cur.fetchone()
                    if not ownership_check:
                        flash('Unauthorized to change this email address.', 'error')
                        logging.warning(f"Unauthorized email change attempt for user ID: {user_id}")
                        return render_template('change_email.html')

                    # Update the email
                    cur.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
                    db.commit()
                    flash('Email changed successfully!', 'success')
                    logging.info(f"Email changed successfully for user ID: {user_id}")
                    return render_template('change_email.html')
        except sqlite3.Error as e:
            db.rollback()
            logging.error(f"Database error during email change: {e}")
            flash('An unexpected error occurred. Please try again later.', 'error')
            return render_template('change_email.html')

    return render_template('change_email.html')

if __name__ == '__main__':
    # Initialize the database (create tables if they don't exist)
    with app.app_context():
        init_db()

    app.run(debug=True, host="0.0.0.0")

