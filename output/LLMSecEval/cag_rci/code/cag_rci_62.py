import os
import secrets
import time
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
from itsdangerous import URLSafeTimedSerializer
from email.message import EmailMessage
import ssl
import smtplib
import logging
import re  # For password complexity validation

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
bcrypt = Bcrypt(app)
limiter = Limiter(app, key_func=get_remote_address, storage_uri="redis://localhost:6379")

DATABASE = 'users.db'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])

logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Database Functions ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until DATETIME
            )
        ''')
        conn.commit()
    finally:
        conn.close()


init_db()


# --- Admin User Creation ---
with app.app_context():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        if count == 0:
            import secrets
            import string
            alphabet = string.ascii_letters + string.digits + string.punctuation
            admin_password = ''.join(secrets.choice(alphabet) for i in range(16))
            hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("admin", hashed_password))
            conn.commit()
            logging.info("Initial admin user created. Password reset required.")
    finally:
        conn.close()


# --- Helper Functions ---
def is_account_locked(username):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT locked_until FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
    finally:
        conn.close()

    if result and result['locked_until']:
        locked_until = result['locked_until']
        if locked_until > time.time():
            return True
    return False


def reset_failed_login_attempts(username):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE username = ?", (username,))
        conn.commit()
    finally:
        conn.close()


def increment_failed_login_attempts(username):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?", (username,))
        conn.commit()
    finally:
        conn.close()

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT failed_login_attempts FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
    finally:
        conn.close()

    if result and result['failed_login_attempts'] >= 5:
        lockout_duration = 300
        locked_until = time.time() + lockout_duration
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET locked_until = ? WHERE username = ?", (locked_until, username))
            conn.commit()
        finally:
            conn.close()
        return True
    return False


def send_reset_email(email, token):
    sender = app.config['MAIL_USERNAME']
    password = app.config['MAIL_PASSWORD']
    receiver = email

    subject = 'Password Reset Request'
    body = f"Click the following link to reset your password: {url_for('reset_password', token=token, _external=True)}"

    em = EmailMessage()
    em['From'] = sender
    em['To'] = receiver
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()
    # Consider disabling insecure protocols:
    # context.options |= ssl.OP_NO_SSLv2
    # context.options |= ssl.OP_NO_SSLv3

    try:
        with smtplib.SMTP_SSL(app.config['MAIL_SERVER'], app.config['MAIL_PORT'], context=context) as smtp:
            smtp.login(sender, password)
            smtp.sendmail(sender, receiver, em.as_string())
        return True
    except Exception as e:
        logging.error(f"Error sending email: {e}")  # Log the error
        return False


# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# --- Password Complexity Validation ---
def validate_password_complexity(password):
    """
    Validates password complexity.  Requires:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 12:
        return "Password must be at least 12 characters long."
    if not re.search("[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search("[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search("[0-9]", password):
        return "Password must contain at least one digit."
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
    return None  # Password is valid


# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_account_locked(username):
            flash('Account is locked. Please try again later.', 'error')
            return render_template('login.html')

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
        finally:
            conn.close()

        if result:
            password_hash = result['password_hash']
            if bcrypt.check_password_hash(password_hash, password):
                reset_failed_login_attempts(username)
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('session_page'))
            else:
                if increment_failed_login_attempts(username):
                    flash('Incorrect username or password. Account locked due to too many failed attempts.', 'error')
                else:
                    flash('Incorrect username or password.', 'error')
        else:
            flash('Incorrect username or password.', 'error')

    return render_template('login.html')


@app.route('/session')
@login_required
def session_page():
    username = session['username']
    return render_template('session.html', username=username)


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE username = ?", (email,))
            result = cursor.fetchone()
        finally:
            conn.close()

        if result:
            username = result['username']
            token = ts.dumps(username, salt='password-reset-salt')
            if send_reset_email(email, token):
                flash('A password reset link has been sent to your email address.', 'info')
                return redirect(url_for('login'))
            else:
                flash('Failed to send password reset email. Please try again later.', 'error')
        else:
            flash('Email address not found.', 'error')

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        username = ts.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('Invalid or expired password reset link.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # --- Password Complexity Check ---
        complexity_error = validate_password_complexity(new_password)
        if complexity_error:
            flash(complexity_error, 'error')
            return render_template('reset_password.html', token=token)

        if new_password == confirm_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hashed_password, username))
                conn.commit()
            finally:
                conn.close()

            flash('Password reset successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match.', 'error')

    return render_template('reset_password.html', token=token)


# --- Error Handling ---
@app.errorhandler(429)
def ratelimit_handler(e):
    flash('Too many requests. Please try again later.', 'error')
    return redirect(url_for('login'))


@app.errorhandler(500)
def internal_server_error(e):
    logging.exception(e)
    return "Internal Server Error", 500


# --- Main ---
if __name__ == '__main__':
    app.run(debug=True)

