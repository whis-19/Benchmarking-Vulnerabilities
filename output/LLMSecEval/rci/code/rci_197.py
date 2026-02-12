import os
from flask import Flask, request, render_template, session, redirect, url_for, flash
from functools import wraps
import secrets  # For generating secure session keys
import hashlib  # For securely hashing sensitive data
import bcrypt  # For password hashing
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging  # For logging errors
from flask_session import Session  # For server-side session management
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.exc import NoResultFound
from urllib.parse import quote_plus

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Securely generate a secret key for the Flask app.  This is crucial for session management.
app.secret_key = secrets.token_hex(32)  # Generates a 32-byte (256-bit) random hex string

# Configure session cookie security
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['SESSION_TYPE'] = 'filesystem'  # Use server-side sessions (filesystem)
app.config['SESSION_FILE_DIR'] = 'flask_session'  # Directory to store session files
app.config['SESSION_PERMANENT'] = False  # Sessions are not permanent
app.config['SESSION_USE_SIGNER'] = True # Ensure session integrity
app.config['SESSION_KEY_PREFIX'] = 'sess:' # Add a prefix to session keys

# Initialize Flask-Session
Session(app)

# Database Configuration (PostgreSQL Example)
DB_USER = os.environ.get('DB_USER', 'your_db_user')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'your_db_password')
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = os.environ.get('DB_PORT', '5432')
DB_NAME = os.environ.get('DB_NAME', 'your_db_name')

# URL-encode the password
encoded_password = quote_plus(DB_PASSWORD)

DATABASE_URL = f"postgresql://{DB_USER}:{encoded_password}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL, echo=False)  # echo=True for debugging SQL
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)  # Store hashed passwords
    # Consider removing SSN entirely.  If absolutely necessary, use tokenization.
    # ssn_last4_hash = Column(String(64), nullable=True) # Remove this if possible

    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"

Base.metadata.create_all(engine)  # Create tables if they don't exist

SessionLocal = sessionmaker(bind=engine)


# Initialize Talisman for security headers
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\'',  # Removed data:
    'font-src': '\'self\'',
    'connect-src': '\'self\'',
    'report-uri': '/csp_report'  # Add a report URI
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script'],
    force_https=True,
    frame_options='SAMEORIGIN',
    x_content_type_options='nosniff',
    x_xss_protection='1; mode=block',
    referrer_policy='strict-origin-when-cross-origin'
)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://" # Use in-memory storage for rate limiting (for simplicity)
)

# In a real application, you would retrieve user data from a database.
# This is a placeholder for demonstration purposes ONLY.  DO NOT store sensitive data like this in real code.
# REMOVE THIS ENTIRE SECTION
# USER_DATA = {
#     "user1": {
#         "username": "user1",
#         "email": "user1@example.com",
#         "password_hash": bcrypt.hashpw("password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),  # Hashed password
#         "ssn_last4_hash": hashlib.sha256("1234".encode('utf-8')).hexdigest()  # Hashed SSN last 4
#     },
#     "user2": {
#         "username": "user2",
#         "email": "user2@example.com",
#         "password_hash": bcrypt.hashpw("password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),  # Hashed password
#         "ssn_last4_hash": hashlib.sha256("5678".encode('utf-8')).hexdigest()  # Hashed SSN last 4
#     }
# }


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Registration Form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        db_session = SessionLocal()
        try:
            # Check if the username or email already exists
            existing_user = db_session.query(User).filter((User.username == username) | (User.email == email)).first()
            if existing_user:
                flash('Username or email already exists.', 'danger')
                return render_template('register.html', form=form)

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            new_user = User(username=username, email=email, password_hash=hashed_password)
            db_session.add(new_user)
            db_session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'danger')
            db_session.rollback()
        finally:
            db_session.close()

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        db_session = SessionLocal()
        try:
            user = db_session.query(User).filter_by(username=username).first()

            if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
                session.clear()  # Clear existing session
                session['username'] = username
                session.regenerate = True  # Regenerate session ID
                flash('Login successful!', 'success')
                return redirect(url_for('info'))
            else:
                flash('Invalid username or password', 'danger')
                return render_template('login.html', form=form)
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred during login. Please try again.', 'danger')
        finally:
            db_session.close()

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/info')
@login_required
def info():
    username = session['username']
    db_session = SessionLocal()
    try:
        user = db_session.query(User).filter_by(username=username).one()
        # NEVER store or transmit the actual SSN.  Only store a hash of the last 4 digits.
        # Display the username and email, but NOT the SSN hash directly.
        # Remove ssn_last4_hash from the template
        return render_template('info.html', username=user.username, email=user.email)
    except NoResultFound:
        logger.error(f"User not found: {username}")
        flash("User not found.", "error")
        return redirect(url_for('login'))
    except Exception as e:
        logger.exception("An unexpected error occurred")
        flash("An unexpected error occurred. Please try again later.", "error")
        return "Internal Server Error", 500
    finally:
        db_session.close()


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/csp_report', methods=['POST'])
def csp_report():
    report_data = request.get_json()
    logger.warning(f"CSP Violation: {report_data}")
    # In a real application, you would want to store this data for analysis.
    return '', 204


if __name__ == '__main__':
    # NEVER run in production with debug=True.  It exposes sensitive information.
    # Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

