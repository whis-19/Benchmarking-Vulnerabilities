import os
from flask import Flask, request, render_template, session, redirect, url_for, flash
from functools import wraps
import secrets  # For generating secure session keys
import bcrypt  # For password hashing
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach  # For sanitizing user input
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)

# Securely generate a secret key for the Flask app.  This is crucial for session management.
# Store the secret key in an environment variable
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# Configure session cookie security
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF

# Initialize Talisman for security headers
# Use nonces for inline scripts
csp_nonce = secrets.token_urlsafe(16)
talisman = Talisman(app,
                    content_security_policy={
                        'default-src': '\'self\'',
                        'script-src': ["'self'", f"'nonce-{csp_nonce}'"],
                        'style-src': '\'self\'',
                        'img-src': '\'self\' data:',
                        'font-src': '\'self\'',
                        'object-src': '\'none\'',
                    },
                    force_https=True,  # Enforce HTTPS
                    frame_options='SAMEORIGIN',
                    x_content_type_options='nosniff',
                    x_xss_protection='1; mode=block',
                    referrer_policy='strict-origin-when-cross-origin')

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example rate limits
)

# Database Configuration (SQLite for simplicity, replace with PostgreSQL, MySQL, etc. for production)
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///site.db')  # Use environment variable or default to SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking modifications for performance

engine = create_engine(DATABASE_URL)
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(60), nullable=False)  # Store password hashes

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

Base.metadata.create_all(engine)  # Create tables if they don't exist
Session = sessionmaker(bind=engine)


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        db_session = Session()
        try:
            user = db_session.query(User).filter_by(username=username).first()
            if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
                session.clear()  # Clear the old session
                session['user_id'] = user.id  # Store user ID in session
                session.regenerate = True # Regenerate the session ID
                flash('Login successful!', 'success')
                return redirect(url_for('info'))
            else:
                flash('Invalid username or password', 'error')
                return render_template('login.html', form=form, error="Invalid credentials", csp_nonce=csp_nonce)
        except SQLAlchemyError as e:
            db_session.rollback()
            flash('Database error occurred. Please try again later.', 'error')
            app.logger.error(f"Database error during login: {e}") # Log the error
            return render_template('login.html', form=form, error="Database error", csp_nonce=csp_nonce)
        finally:
            db_session.close()

    return render_template('login.html', form=form, csp_nonce=csp_nonce)


@app.route('/logout')
@login_required
def logout():
    session.clear()  # Clear all session data, including user_id
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))


@app.route('/info')
@login_required
def info():
    user_id = session['user_id']
    db_session = Session()
    try:
        user = db_session.query(User).filter_by(id=user_id).first()
        if user:
            # Sanitize the username and email before displaying them
            safe_username = bleach.clean(user.username)
            safe_email = bleach.clean(user.email)
            return render_template('info.html', username=safe_username, email=safe_email)
        else:
            return "User not found", 404
    except SQLAlchemyError as e:
        app.logger.error(f"Database error during info retrieval: {e}")
        return "Database error", 500
    finally:
        db_session.close()


@app.route('/')
def index():
    return redirect(url_for('login'))


if __name__ == '__main__':
    # NEVER run in production with debug=True.  It exposes sensitive information.
    # Use a production WSGI server like gunicorn or uWSGI.
    # app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

