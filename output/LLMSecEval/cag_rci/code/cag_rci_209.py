from flask import Flask, request, session, redirect, url_for, flash, render_template
from flask_wtf import CSRFProtect
import secrets
from email_validator import validate_email, EmailNotValidError
import logging
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash  # For password hashing
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded  # Import the rate limit exception

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",  # Use a persistent storage for production (e.g., redis://localhost:6379)
    strategy="fixed-window"
)

# Database connection (example - adapt to your setup)
DATABASE = 'users.db'  # Replace with your database file

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

# Password hashing functions
def hash_password(password):
    return generate_password_hash(password)

def verify_password(password, password_hash):
    return check_password_hash(password_hash, password)

def is_valid_email(email):
    try:
        emailinfo = validate_email(email, check_deliverability=False)  # Consider True for production
        email = emailinfo.normalized
        return True
    except EmailNotValidError as e:
        logging.warning(f"Invalid email format: {str(e)}")  # Log the error
        return False

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()

                if user and verify_password(password, user['password_hash']):
                    session['user_id'] = user['id']
                    session.regenerate()
                    flash('Login successful!', 'success')
                    logging.info(f"User {username} logged in successfully.")
                    return redirect(url_for('index'))
                else:
                    # Generic error message to prevent username enumeration
                    flash('Invalid credentials.', 'error')
                    logging.warning(f"Failed login attempt for user {username}.")
        except sqlite3.Error as e:
            logging.error(f"Database error during login: {e}")
            flash('An error occurred during login. Please try again.', 'error')
        except RateLimitExceeded as e:  # Catch the specific rate limit exception
            flash('Too many login attempts. Please try again later.', 'error')
            logging.warning(f"Rate limit exceeded for user {username or 'unknown'}.")
            print(f"Rate limit error: {e}")
        except Exception as e:  # Catch other unexpected exceptions
            logging.exception("An unexpected error occurred during login.") # Log the full exception traceback
            flash('An unexpected error occurred. Please try again later.', 'error')


    return render_template('login.html')

# Example of user registration (add this to your application)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if not is_valid_email(email):
            flash('Invalid email address.', 'error')
            return render_template('register.html')

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()

                # Check if username already exists
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    flash('Username already exists.', 'error')
                    return render_template('register.html')

                # Hash the password
                password_hash = hash_password(password)

                # Insert the new user
                cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, password_hash, email))
                conn.commit()

                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))

        except sqlite3.Error as e:
            logging.error(f"Database error during registration: {e}")
            flash('An error occurred during registration. Please try again.', 'error')

    return render_template('register.html')

if __name__ == '__main__':
    #  Example of setting session cookie attributes
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
    app.config['SESSION_COOKIE_SECURE'] = True  # Only transmit over HTTPS
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

    app.run(debug=True, ssl_context="adhoc") # Enable HTTPS for local development

