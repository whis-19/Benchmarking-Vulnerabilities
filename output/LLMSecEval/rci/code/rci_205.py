from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_talisman import Talisman
from flask_sqlalchemy import SQLAlchemy
import os
from functools import wraps

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Use SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking for performance
db = SQLAlchemy(app)

# --- Security Headers with Flask-Talisman ---
talisman = Talisman(app,
                   content_security_policy={
                       'default-src': '\'self\'',
                       'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Example: Allow scripts from a CDN
                       'style-src': ['\'self\'', 'https://cdn.jsdelivr.net'], # Example: Allow styles from a CDN
                       'img-src': ['\'self\'', 'data:'], # Allow images from self and data URIs
                   },
                   content_security_policy_nonce_in=['script-src', 'style-src'], # Enable nonces for inline scripts and styles
                   force_https=True,  # Enforce HTTPS
                   frame_options='DENY',
                   strict_transport_security=True,
                   content_type_nosniff=True,
                   referrer_policy='same-origin'
                   )

# --- Database Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Increased length for bcrypt
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

with app.app_context():
    db.create_all()  # Create the database tables

# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# --- Account Lockout Decorator ---
from datetime import datetime, timedelta
from flask import abort

def account_lockout(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        username = request.form.get('username')  # Assuming username is in the form
        user = User.query.filter_by(username=username).first()

        if user and user.locked_until and user.locked_until > datetime.utcnow():
            time_remaining = user.locked_until - datetime.utcnow()
            flash(f"Account locked. Please try again in {time_remaining.seconds // 60} minutes.", 'error')
            return redirect(url_for('login'))  # Redirect to login page

        return func(*args, **kwargs)
    return wrapper


# --- Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256') # Use pbkdf2:sha256
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@account_lockout
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session['username'] = user.username
            user.failed_login_attempts = 0  # Reset failed attempts on successful login
            user.locked_until = None
            db.session.commit()
            flash('You have been logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Account Lockout Implementation
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)  # Lock for 15 minutes
                    flash('Too many failed login attempts. Account locked for 15 minutes.', 'error')
                else:
                    flash('Login Unsuccessful. Please check username and password', 'error')
                db.session.commit()
            else:
                flash('Login Unsuccessful. Please check username and password', 'error')

    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        flash('Please log in to access the dashboard.', 'info')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# --- CSRF Protection (Flask-WTF handles this implicitly when using forms) ---
# --- HTTPS Enforcement (Handled by Flask-Talisman) ---

# --- Input Validation (Handled by WTForms validators) ---

# --- Rate Limiting (Consider using Flask-Limiter for more robust rate limiting) ---
# --- Example using Flask-Limiter (install with pip install Flask-Limiter) ---
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
# limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
# @app.route("/api/")
# @limiter.limit("10 per minute")
# def my_api():
#     return "API Response"

# --- Security Headers (Handled by Flask-Talisman) ---

# --- Running the App ---
if __name__ == '__main__':
    # Create the database tables within the application context
    with app.app_context():
        db.create_all()
    # NEVER USE debug=True IN PRODUCTION!
    # Use a proper WSGI server like Gunicorn or uWSGI in production.
    app.run(debug=True)

