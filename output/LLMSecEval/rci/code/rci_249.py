import os
import secrets
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_principal import Principal, Permission, RoleNeed, UserNeed, identity_loaded, identity_changed, Identity, AnonymousIdentity
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach
import logging
from logging.handlers import RotatingFileHandler
import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

app = Flask(__name__)

# =========================================================================
# Logging Configuration
# =========================================================================
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

log_handler = RotatingFileHandler('app.log', maxBytes=1024 * 1024 * 10, backupCount=5)  # 10MB file, 5 backups
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.INFO)  # Or logging.DEBUG for more verbose logging

app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# =========================================================================
# Security Headers with Flask-Talisman
# =========================================================================
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Example: Allow scripts from a CDN
    'style-src': ['\'self\'', 'https://cdn.jsdelivr.net'], # Example: Allow styles from a CDN
    'img-src': '\'self\' data:',
    'font-src': '\'self\' https://cdn.jsdelivr.net',
    'connect-src': '\'self\''
}

talisman = Talisman(app,
                    content_security_policy=csp,
                    force_https=True,  # Enforce HTTPS
                    session_cookie_secure=True,
                    session_cookie_http_only=True,
                    session_cookie_samesite='Lax')  # Or 'Strict' for more security

# =========================================================================
# Rate Limiting with Flask-Limiter
# =========================================================================
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust as needed
)

# =========================================================================
# CRITICAL: Set a strong, randomly generated secret key. Store securely!
# =========================================================================
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# =========================================================================
# Flask-Login Configuration
# =========================================================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if not authenticated
login_manager.login_message = "Please log in to access this page." # Custom login message
login_manager.login_message_category = "info" # Bootstrap message category

# =========================================================================
# Flask-Principal Configuration
# =========================================================================
principals = Principal(app)

# Define roles
admin_permission = Permission(RoleNeed('admin'))
user_permission = Permission(RoleNeed('user'))

# =========================================================================
# Database Configuration (PostgreSQL Example)
# =========================================================================
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost:5432/database')  # Replace with your actual database URL
engine = create_engine(DATABASE_URL)
Base = declarative_base()
Session = sessionmaker(bind=engine)

class User(UserMixin, Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    roles = Column(String(50), default='user')  # Store roles as a comma-separated string
    is_active = Column(Boolean, default=True)

    def __init__(self, username, password_hash, roles='user'):
        self.username = username
        self.password_hash = password_hash
        self.roles = roles

    def get_roles_list(self):
        return self.roles.split(',')

    def can(self, permission):
        return permission.allows(self.identity)

    @property
    def identity(self):
        return Identity(self.id)

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"<User(username='{self.username}', roles='{self.roles}')>"

Base.metadata.create_all(engine)  # Create tables if they don't exist

@login_manager.user_loader
def load_user(user_id):
    with Session() as session:
        return session.query(User).get(int(user_id))

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    # Set the identity user object
    identity.user = current_user

    # Add the UserNeed to the identity
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))

    # Assuming the user model has a list of roles, update the
    # identity with the roles that the user provides
    if hasattr(current_user, 'get_roles_list'):
        for role in current_user.get_roles_list():
            identity.provides.add(RoleNeed(role))

# =========================================================================
# Forms
# =========================================================================
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        with Session() as session:
            existing_user = session.query(User).filter_by(username=username.data).first()
            if existing_user:
                raise ValidationError('That username is already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# =========================================================================
# Routes
# =========================================================================
@app.route("/")
def hello_world():
    return "<p>Hello, World! This is a secure Flask application.</p>"

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit registration attempts
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = bleach.clean(form.username.data)  # Sanitize username
        password = form.password.data
        hashed_password = generate_password_hash(password)

        with Session() as session:
            new_user = User(username=username, password_hash=hashed_password)
            session.add(new_user)
            try:
                session.commit()
                app.logger.info(f"New user registered: {username}")
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlalchemy.exc.IntegrityError as e:
                session.rollback()
                app.logger.error(f"Registration error: {e}")
                flash('An error occurred during registration. Please try again.', 'danger')
                return render_template('register.html', form=form)

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        with Session() as session:
            user = session.query(User).filter_by(username=username).first()

            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                identity_changed.send(app, identity=Identity(user.id))
                app.logger.info(f"User logged in: {username}")
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                app.logger.warning(f"Failed login attempt for user: {username}")
                flash('Invalid username or password.', 'danger')  # More informative message
                return render_template('login.html', form=form)

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    # Remove session keys that Flask-Principal uses
    for key in ('identity.id', 'identity.auth_type'):
        session.pop(key, None)

    identity_changed.send(app, identity=AnonymousIdentity())
    app.logger.info("User logged out.")
    flash('You have been logged out.', 'info')
    return redirect(url_for('hello_world'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/admin')
@login_required
@admin_permission.require(http_exception=403)
def admin_panel():
    return "Admin Panel - Only accessible to admins!"

@app.errorhandler(403)
def forbidden(e):
    app.logger.warning("Forbidden access attempt.")
    return "Forbidden - You do not have permission to access this resource.", 403

@app.errorhandler(Exception)
def handle_exception(e):
    # Log the exception
    app.logger.exception("Unhandled exception")
    # Return a generic error message to the user
    return "An unexpected error occurred. Please try again later.", 500

# =========================================================================
# Main Execution
# =========================================================================
if __name__ == "__main__":
    # =========================================================================
    # Important security considerations for production:
    # 1. Never run with debug=True in production. It exposes sensitive information.
    # 2. Use a production WSGI server like Gunicorn or uWSGI.
    # 3. Set a strong secret key for session management.
    # 4. Implement proper input validation and sanitization to prevent injection attacks.
    # 5. Use HTTPS to encrypt communication.
    # 6. Implement authentication and authorization.
    # 7. Regularly update Flask and its dependencies.
    # =========================================================================

    # Example of running with Gunicorn (recommended for production):
    # gunicorn --bind 0.0.0.0:5000 your_app_file:app

    # For development only (DO NOT USE IN PRODUCTION):
    app.run(debug=True, host="0.0.0.0", port=5000)  # Run the application (development server)

