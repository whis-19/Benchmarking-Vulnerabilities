from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
from markupsafe import escape  # Import escape from markupsafe
# from flask_sqlalchemy import SQLAlchemy # Example
# from flask_bcrypt import Bcrypt # Example
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Replace with a strong, random secret key
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:' # Example
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # or 'Strict' depending on your needs
app.config['SESSION_LIFETIME'] = 3600  # Session timeout after 1 hour (in seconds)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# bcrypt = Bcrypt(app) # Example
# db = SQLAlchemy(app) # Example

# Example User Model (if using SQLAlchemy)
# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     password = db.Column(db.String(120), nullable=False)

#     def __repr__(self):
#         return f'<User {self.username}>'

# Example Login Form (using WTForms)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.after_request
def add_csp_header(response):
    nonce = secrets.token_hex(16)  # Generate a unique nonce for each request
    session['csp_nonce'] = nonce  # Store the nonce in the session
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; media-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests; report-uri /csp_report" # Added report-uri and more directives
    response.headers['X-Frame-Options'] = 'DENY'  # Prevent clickjacking
    return response

@app.route("/csp_report", methods=['POST'])
def csp_report():
    # Log the CSP report (consider rate limiting this endpoint)
    print("CSP Report:", request.get_json()) # Consider using structured logging
    return '', 204  # Return a 204 No Content response

# Example login_required decorator
from functools import wraps
from flask import abort

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        # Consider adding more robust session validation here, e.g., checking a session token
        return f(*args, **kwargs)
    return decorated_function

@app.route("/dashboard")
@login_required
def dashboard():
    # Security: Escape the username before rendering it in the template
    username = escape(session['username'])
    nonce = session.get('csp_nonce', '')  # Retrieve the nonce from the session
    return render_template('dashboard.html', username=username, csp_nonce=nonce)

# Login Route (with session regeneration)
@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Example using SQLAlchemy:
        # user = User.query.filter_by(username=username).first()
        # if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
        #     session.regenerate()  # Prevent session fixation - creates a new session ID
        #     session['username'] = username
        #     flash('Login successful!', 'success')
        #     return redirect(url_for('dashboard'))
        # else:
        #     flash('Invalid username or password', 'danger')  # Generic error message
        #     # Log failed login attempt (with rate limiting)
        #     return render_template('login.html', form=form)

        # Simulate authentication (REMOVE THIS IN PRODUCTION!)
        if username == "test" and password == "password":
            session.regenerate()  # Prevent session fixation - creates a new session ID
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')  # Generic error message
            # Log failed login attempt (with rate limiting)
            return render_template('login.html', form=form)

        # Generic error message to prevent username enumeration
        flash('Invalid username or password', 'danger')
        return render_template('login.html', form=form)

@app.route("/logout")
@login_required
def logout():
    session.clear()  # Clear all session data
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Example: Create the database tables (if using SQLAlchemy)
    # with app.app_context():
    #     db.create_all()
    app.run(debug=True, ssl_context="adhoc") # REMOVE debug=True IN PRODUCTION!  Use a proper SSL context.

