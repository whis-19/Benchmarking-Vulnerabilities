import os
import hashlib
import secrets
from flask import Flask, request, render_template, redirect, url_for, session, abort
from functools import wraps
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length
import sqlite3
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import html
from flask_talisman import Talisman  # Import Flask-Talisman

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# Configuration (ideally loaded from a separate file or environment variables)
DATABASE_FILE = "users.db"
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")  # Get from environment variable, default to "admin"
ADMIN_CREATED_FLAG = "admin_created"  # Key for the database flag

# --- Security Configuration ---
# HTTPS Enforcement (example - configure your web server for HTTPS)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Or 'Strict' depending on your needs

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# CSRF Protection
csrf = CSRFProtect(app)

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Headers with Flask-Talisman ---
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': '\'self\'',  # Add 'unsafe-inline' if needed, but avoid if possible
        'style-src': '\'self\'',
        'img-src': '\'self\' data:',
        'font-src': '\'self\'',
    },
    force_https=True,  # Enforce HTTPS
    frame_options='SAMEORIGIN',  # Prevent clickjacking
    content_type_nosniff=True,  # Prevent MIME sniffing
    strict_transport_security=True,  # Enforce HTTPS for future requests
    strict_transport_security_max_age=31536000,  # One year
    strict_transport_security_include_subdomains=True,
    referrer_policy='same-origin'
)


# --- Database Functions ---
def create_user_table():
    """Creates the user table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT,
                salt TEXT,
                is_admin INTEGER DEFAULT 0,
                failed_login_attempts INTEGER DEFAULT 0,
                locked INTEGER DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        conn.close()

def get_user(username):
    """Retrieves a user from the database."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, password_hash, salt, is_admin, failed_login_attempts, locked FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user:
            return {
                "username": user[0],
                "password_hash": user[1],
                "salt": user[2],
                "is_admin": bool(user[3]),
                "failed_login_attempts": user[4],
                "locked": bool(user[5])
            }
        else:
            return None
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return None
    finally:
        conn.close()

def create_user(username, password, is_admin=False):
    """Creates a new user in the database."""
    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash, salt, is_admin) VALUES (?, ?, ?, ?)",
                       (username, password_hash, salt, is_admin))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        logging.warning(f"Username already exists: {username}")
        return False  # Username already exists
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False
    finally:
        conn.close()

def update_password(username, new_password):
    """Updates a user's password in the database."""
    salt = secrets.token_hex(16)
    password_hash = hash_password(new_password, salt)
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?", (password_hash, salt, username))
        conn.commit()
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False
    finally:
        conn.close()

def increment_failed_login_attempts(username):
    """Increments the failed login attempts for a user."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?", (username,))
        conn.commit()
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False
    finally:
        conn.close()

def reset_failed_login_attempts(username):
    """Resets the failed login attempts for a user."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET failed_login_attempts = 0 WHERE username = ?", (username,))
        conn.commit()
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False
    finally:
        conn.close()

def lock_account(username):
    """Locks a user account."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET locked = 1 WHERE username = ?", (username,))
        conn.commit()
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False
    finally:
        conn.close()

def unlock_account(username):
    """Unlocks a user account."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET locked = 0, failed_login_attempts = 0 WHERE username = ?", (username,))
        conn.commit()
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False
    finally:
        conn.close()

def set_setting(key, value):
    """Sets a setting in the database."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False
    finally:
        conn.close()

def get_setting(key):
    """Gets a setting from the database."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        result = cursor.fetchone()
        if result:
            return result[0]
        else:
            return None
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return None
    finally:
        conn.close()


# --- Hashing Functions ---
def hash_password(password, salt):
    """Hashes the password using PBKDF2-HMAC with a salt."""
    # Use a strong hashing algorithm like PBKDF2-HMAC
    # The salt should be unique for each user and stored securely
    # The iterations and key length should be chosen based on security requirements
    # and computational cost.  Adjust as needed.
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 500000, 128).hex()

def verify_password(password, password_hash, salt):
    """Verifies the password against the stored hash and salt."""
    # Hash the provided password with the stored salt
    hashed_password = hash_password(password, salt)
    # Compare the generated hash with the stored hash
    return hashed_password == password_hash

# --- Authentication Decorator ---
def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        user = get_user(session['username'])
        if not user or not user['is_admin']:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# --- Forms ---
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class FirstLoginForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Set Password')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm New Password')
    submit = SubmitField('Change Password')

# --- Routes ---

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    """Displays the login form and handles the login process."""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = get_user(username)

        if user:
            if user['locked']:
                logging.warning(f"Login attempt for locked account: {username}")
                return render_template('login.html', form=form, error="Account is locked. Contact an administrator.")

            if verify_password(password, user['password_hash'], user['salt']):
                session['username'] = username
                reset_failed_login_attempts(username)
                logging.info(f"Successful login: {username}")
                if user['is_admin']:
                    return redirect(url_for('admin_page'))
                else:
                    return redirect(url_for('user_page'))
            else:
                increment_failed_login_attempts(username)
                failed_attempts = user['failed_login_attempts'] + 1
                logging.warning(f"Failed login attempt for user: {username}, attempts: {failed_attempts}")
                if failed_attempts >= 5:  # Lock after 5 failed attempts
                    lock_account(username)
                    logging.critical(f"Account locked due to multiple failed login attempts: {username}")
                    return render_template('login.html', form=form, error="Invalid username or password. Account locked after multiple failed attempts.")
                else:
                    return render_template('login.html', form=form, error="Invalid username or password. Attempts remaining: {}".format(5 - failed_attempts))
        else:
            return render_template('login.html', form=form, error="Invalid username or password")

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Logs the user out."""
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
@admin_required
def admin_page():
    """Admin page (requires login and admin privileges)."""
    return render_template('admin.html', username=session['username'])

@app.route('/user')
@login_required
def user_page():
    """Regular user page (requires login)."""
    username = html.escape(session['username']) #Sanitize username for display
    return render_template('user.html', username=username)

@app.route('/first_login', methods=['GET', 'POST'])
def first_login():
    """Handles the first login and password setup for the admin user."""
    # Check if the admin user has already been created
    if get_setting(ADMIN_CREATED_FLAG) == "True":
        logging.warning("Attempt to access first_login after admin user creation.")
        abort(404)  # Or redirect to a more appropriate page

    form = FirstLoginForm()
    if form.validate_on_submit():
        username = ADMIN_USERNAME  # Use the configured admin username
        password = form.password.data

        if create_user(username, password, is_admin=True):
            logging.info(f"Admin user created: {username}")
            # Set the admin created flag in the database
            set_setting(ADMIN_CREATED_FLAG, "True")
            return redirect(url_for('login'))  # Redirect to login after successful setup
        else:
            logging.error("Failed to create admin user. Username may already exist.")
            return render_template('first_login.html', form=form, error="Failed to create admin user.  Username may already exist.")

    return render_template('first_login.html', form=form)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allows a logged-in user to change their password."""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        old_password = form.old_password.data
        new_password = form.new_password.data

        user = get_user(session['username'])

        if not user or not verify_password(old_password, user['password_hash'], user['salt']):
            logging.warning(f"Invalid old password attempt for user: {session['username']}")
            return render_template('change_password.html', form=form, error="Invalid old password")

        if update_password(session['username'], new_password):
            logging.info(f"Password changed successfully for user: {session['username']}")
            return render_template('change_password.html', form=form, success="Password changed successfully!")
        else:
            logging.error(f"Failed to update password for user: {session['username']}")
            return render_template('change_password.html', form=form, error="Failed to update password.")

    return render_template('change_password.html', form=form)

# --- Error Handling ---
@app.errorhandler(403)
def forbidden(e):
    logging.warning(f"Forbidden access attempt from user: {session.get('username', 'N/A')}")
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    logging.warning(f"Page not found: {request.path}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")  # Log the full exception
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Create the user table if it doesn't exist
    create_user_table()

    # Check if the admin user exists.  If not, redirect to first_login.
    if not get_user(ADMIN_USERNAME) and get_setting(ADMIN_CREATED_FLAG) != "True":
        print("Admin user not found.  Please visit /first_login to set up the admin password.")
        #  In a real application, you might want to handle this more gracefully,
        #  perhaps by displaying a message on the login page or redirecting
        #  automatically.  For this example, we'll just print a message.

    app.run(debug=True)

