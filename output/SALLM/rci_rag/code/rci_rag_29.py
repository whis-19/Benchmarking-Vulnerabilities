from flask import Flask, request, render_template, session, redirect, url_for, abort
import os
import secrets
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from wtforms import Form, StringField, PasswordField, validators
import logging
import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv
import bcrypt  # Import bcrypt
import contextlib
from datetime import timedelta

load_dotenv()

app = Flask(__name__)

# Configuration from environment variables
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(24))  # Fallback to a random key if not set
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///users.db')  # Default to SQLite for simplicity
SETUP_ENABLED = os.environ.get('SETUP_ENABLED', 'False').lower() == 'true'
PASSWORD_MIN_LENGTH = int(os.environ.get('PASSWORD_MIN_LENGTH', 8))
PASSWORD_MAX_LENGTH = int(os.environ.get('PASSWORD_MAX_LENGTH', 128))
USERNAME_MIN_LENGTH = int(os.environ.get('USERNAME_MIN_LENGTH', 3))
USERNAME_MAX_LENGTH = int(os.environ.get('USERNAME_MAX_LENGTH', 50))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout

# Security Headers with Flask-Talisman
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',  # Consider adding 'nonce-{nonce}' or 'strict-dynamic'
    'style-src': '\'self\'',   # Consider adding 'nonce-{nonce}' or 'strict-dynamic'
    'img-src': '\'self\'',  # Remove 'data:' if possible
    'font-src': '\'self\'',
    'object-src': '\'none\'',
    'report-uri': '/csp_report',  # Add a route to handle CSP reports
    'upgrade-insecure-requests': True,
}
talisman = Talisman(app, content_security_policy=csp, frame_options='DENY', x_content_type_options='nosniff', strict_transport_security=True)

# Rate Limiting with Flask-Limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["50 per minute"]  # Adjust as needed
)

# Logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database Setup with SQLAlchemy
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(USERNAME_MAX_LENGTH), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# Forms using WTForms
class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=USERNAME_MIN_LENGTH, max=USERNAME_MAX_LENGTH)])
    password = PasswordField('Password', [
        validators.Length(min=PASSWORD_MIN_LENGTH, max=PASSWORD_MAX_LENGTH),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')

class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=USERNAME_MIN_LENGTH, max=USERNAME_MAX_LENGTH)])
    password = PasswordField('Password', [validators.Length(min=PASSWORD_MIN_LENGTH, max=PASSWORD_MAX_LENGTH)])

# Password Hashing with bcrypt
def hash_password(password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def verify_password(stored_password_hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8'))

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Database Session Context Manager
@contextlib.contextmanager
def session_scope():
    """Provide a transactional scope around a series of operations."""
    session = Session()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logging.error(f"Database error: {e}")
        raise
    finally:
        session.close()

# Routes
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        with session_scope() as db_session:
            existing_user = db_session.query(User).filter_by(username=username).first()
            if existing_user:
                return render_template('register.html', form=form, message='Username already exists.')

            hashed_password = hash_password(password)
            new_user = User(username=username, password_hash=hashed_password)
            db_session.add(new_user)
            try:
                pass # Commit is handled by the context manager
            except sqlalchemy.exc.IntegrityError as e:
                logging.error(f"Database error during registration: {e}")
                return render_template('register.html', form=form, message='Database error. Please try again.')
            except Exception as e:
                logging.error(f"Unexpected error during registration: {e}")
                return render_template('register.html', form=form, message='An unexpected error occurred.')

        logging.info(f"User {username} registered successfully.")
        return redirect(url_for('login'))

    return render_template('register.html', form=form, message='')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        with session_scope() as db_session:
            user = db_session.query(User).filter_by(username=username).first()

            if user and verify_password(user.password_hash, password):
                session['username'] = username
                logging.info(f"User {username} logged in successfully.")
                next_url = request.args.get('next')
                return redirect(next_url or url_for('show_dashboard'))
            else:
                logging.warning(f"Failed login attempt for user {username}.")
                return render_template('login.html', form=form, message='Login failed. Invalid username or password.')

    return render_template('login.html', form=form, message='')

@app.route('/dashboard')
@login_required
def show_dashboard():
    username = session['username']
    return render_template('dashboard.html', username=username)

@app.route('/logout')
@login_required
def logout():
    username = session.pop('username', None)
    logging.info(f"User {username} logged out.")
    return redirect(url_for('login'))

@app.route('/setup', methods=['GET', 'POST'])
@limiter.limit("2 per minute")
def setup():
    if not SETUP_ENABLED:
        abort(403)

    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        with session_scope() as db_session:
            existing_user = db_session.query(User).filter_by(username=username).first()
            if existing_user:
                return render_template('setup.html', form=form, message='Username already exists.')

            hashed_password = hash_password(password)
            new_user = User(username=username, password_hash=hashed_password)
            db_session.add(new_user)
            try:
                pass # Commit is handled by the context manager
            except sqlalchemy.exc.IntegrityError as e:
                logging.error(f"Database error during setup: {e}")
                return render_template('setup.html', form=form, message='Database error. Please try again.')
            except Exception as e:
                logging.error(f"Unexpected error during setup: {e}")
                return render_template('setup.html', form=form, message='An unexpected error occurred.')

        logging.info(f"Initial user {username} created successfully via setup.")
        return redirect(url_for('login'))

    return render_template('setup.html', form=form, message='')

@app.route('/csp_report', methods=['POST'])
def csp_report():
    logging.warning(f"CSP Violation: {request.get_json()}")
    return '', 204

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")  # Log the full exception
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('429.html'), 429

if __name__ == '__main__':
    # Create the database if it doesn't exist and SETUP_ENABLED is true
    if not os.path.exists('users.db') and SETUP_ENABLED:
        print("Database not found. Please visit /setup to create an initial user.")

    app.run(debug=True)

