from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import os
import re  # For regular expressions
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
from functools import wraps
from flask_wtf.csrf import CSRFProtect
import secrets
import logging
from flask_talisman import Talisman
from urllib.parse import urlparse

app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or secrets.token_urlsafe(24)  # Get from env var, use secrets for generation
app.config['DATABASE'] = os.environ.get('DATABASE_PATH') or 'users.db'  # Allow database path to be configured
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF (modern browsers)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # Session timeout
app.config['RESET_TOKEN_EXPIRY'] = timedelta(hours=1) # Password reset token expiry time

# --- CSRF Protection ---
csrf = CSRFProtect(app)

# --- Rate Limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri=os.environ.get('REDIS_URL') or "redis://localhost:6379"  # Use Redis, get URL from env
)

# --- Logging ---
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Security Headers ---
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://stackpath.bootstrapcdn.com'], # Add CDNs if needed
    'style-src': ['\'self\'', 'https://stackpath.bootstrapcdn.com'],
    'img-src': '\'self\' data:',
    'font-src': 'https://stackpath.bootstrapcdn.com',
}

talisman = Talisman(app,
                    content_security_policy=csp,
                    frame_options='SAMEORIGIN',
                    force_https=True, # Only enable in production
                    session_cookie_secure=True,
                    session_cookie_http_only=True,
                    session_cookie_samesite='Lax')

# --- Database Initialization (Run once) ---
def init_db():
    db_path = app.config['DATABASE']
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)

    with sqlite3.connect(db_path) as db:
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expiry_time DATETIME NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()
    logging.info("Database initialized successfully.")


# --- Helper function to get database connection ---
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn

# --- Login Required Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to view this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Registration Route ---
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit registration attempts
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # --- Input Validation ---
        if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
            flash("Invalid username format.  Must be 3-20 characters, alphanumeric and underscores only.", 'error')
            return render_template('register.html')

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email address.", 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", 'error')
            return render_template('register.html')

        if not re.search(r"[a-z]", password):
            flash("Password must contain at least one lowercase letter.", 'error')
            return render_template('register.html')

        if not re.search(r"[A-Z]", password):
            flash("Password must contain at least one uppercase letter.", 'error')
            return render_template('register.html')

        if not re.search(r"[0-9]", password):
            flash("Password must contain at least one number.", 'error')
            return render_template('register.html')

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            flash("Password must contain at least one special character.", 'error')
            return render_template('register.html')

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                           (username, hashed_password.decode('utf-8'), email))  # Store hash as string
            conn.commit()
            conn.close()
            flash('Registration successful. Please log in.', 'success')
            logging.info(f"User {username} registered successfully from {request.remote_addr}")
            return redirect(url_for('login'))  # Redirect to login after registration
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed: users.username" in str(e):
                flash('Username already exists', 'error')
            elif "UNIQUE constraint failed: users.email" in str(e):
                flash('Email already exists', 'error')
            else:
                flash('Registration error. Please try again.', 'error')
            logging.error(f"Registration failed for user {username} from {request.remote_addr}: {e}")
            return render_template('register.html')
        except Exception as e:
            flash('Registration error. Please try again.', 'error')
            logging.exception(f"Registration failed for user {username} from {request.remote_addr}: {e}")
            return render_template('register.html')

    return render_template('register.html')


# --- Login Route ---
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Limit login attempts
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()

            if user:
                stored_password_hash = user['password_hash']
                if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                    # Authentication successful
                    session['username'] = username  # Store username in session
                    session.permanent = True  # Make session permanent
                    session.regenerate() # Regenerate session ID
                    flash('Login successful!', 'success')
                    logging.info(f"User {username} logged in successfully from {request.remote_addr}")
                    return redirect(url_for('home'))
                else:
                    flash('Invalid username or password', 'error')
                    logging.warning(f"Failed login attempt for user {username} from {request.remote_addr}: Invalid password")
                    return render_template('login.html')
            else:
                flash('Invalid username or password', 'error')
                logging.warning(f"Failed login attempt for user {username} from {request.remote_addr}: User not found")
                return render_template('login.html')
        except Exception as e:
            logging.exception(f"Error during login for user {username} from {request.remote_addr}: {e}")
            flash("An error occurred during login.", "error")
            return render_template('login.html')

    return render_template('login.html')


# --- Home Route (Requires Login) ---
@app.route('/home')
@login_required
def home():
    return render_template('home.html', username=session['username'])


# --- Logout Route ---
@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)  # Remove username from session
    flash('You have been logged out.', 'info')
    logging.info(f"User logged out from {request.remote_addr}")
    return redirect(url_for('login'))

# --- Password Reset Request Route ---
@app.route('/reset_password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def reset_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()

            if user:
                user_id = user['id']
                token = secrets.token_urlsafe(32)
                expiry_time = datetime.utcnow() + app.config['RESET_TOKEN_EXPIRY']

                cursor.execute("INSERT INTO password_reset_tokens (token, user_id, expiry_time) VALUES (?, ?, ?)",
                               (token, user_id, expiry_time))
                conn.commit()
                conn.close()

                reset_link = url_for('reset_password_confirm', token=token, _external=True)
                # TODO: Send email with reset_link
                print(f"Reset link: {reset_link}") # Replace with actual email sending
                flash('Password reset link sent to your email address.', 'info')
                logging.info(f"Password reset requested for email {email} from {request.remote_addr}")
            else:
                flash('No account found with that email address.', 'error')
                logging.warning(f"Password reset requested for non-existent email {email} from {request.remote_addr}")
        except Exception as e:
            conn.rollback()
            flash('An error occurred. Please try again.', 'error')
            logging.exception(f"Error during password reset request for email {email} from {request.remote_addr}: {e}")
            conn.close()

        return redirect(url_for('login'))
    return render_template('reset_password.html')

# --- Password Reset Confirmation Route ---
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_confirm(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id, expiry_time FROM password_reset_tokens WHERE token = ?", (token,))
        token_data = cursor.fetchone()

        if token_data:
            if datetime.utcnow() < token_data['expiry_time']:
                if request.method == 'POST':
                    password = request.form['password']

                    # Password validation (same as registration)
                    if len(password) < 8:
                        flash("Password must be at least 8 characters long.", 'error')
                        return render_template('reset_password_confirm.html', token=token)

                    if not re.search(r"[a-z]", password):
                        flash("Password must contain at least one lowercase letter.", 'error')
                        return render_template('reset_password_confirm.html', token=token)

                    if not re.search(r"[A-Z]", password):
                        flash("Password must contain at least one uppercase letter.", 'error')
                        return render_template('reset_password_confirm.html', token=token)

                    if not re.search(r"[0-9]", password):
                        flash("Password must contain at least one number.", 'error')
                        return render_template('reset_password_confirm.html', token=token)

                    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
                        flash("Password must contain at least one special character.", 'error')
                        return render_template('reset_password_confirm.html', token=token)

                    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                    user_id = token_data['user_id']

                    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_password.decode('utf-8'), user_id))
                    cursor.execute("DELETE FROM password_reset_tokens WHERE token = ?", (token,)) # Invalidate token
                    conn.commit()
                    conn.close()

                    flash('Password reset successfully. Please log in.', 'success')
                    logging.info(f"Password reset successfully for user ID {user_id} from {request.remote_addr}")
                    return redirect(url_for('login'))
                else:
                    return render_template('reset_password_confirm.html', token=token)
            else:
                flash('Password reset token has expired.', 'error')
                logging.warning(f"Password reset attempt with expired token {token} from {request.remote_addr}")
        else:
            flash('Invalid password reset token.', 'error')
            logging.warning(f"Password reset attempt with invalid token {token} from {request.remote_addr}")
    except Exception as e:
        conn.rollback()
        flash('An error occurred. Please try again.', 'error')
        logging.exception(f"Error during password reset confirmation for token {token} from {request.remote_addr}: {e}")
        conn.close()

    return redirect(url_for('login'))


# --- Templates ---

# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    logging.warning(f"404 error: {request.path} from {request.remote_addr}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f"500 error: {e} from {request.remote_addr}")
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def unhandled_exception(e):
    logging.exception(f"Unhandled exception: {e} from {request.remote_addr}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=False)  # Don't use debug mode in production!

