import os
import secrets
from urllib.parse import urlparse

from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# from flask_sslify import SSLify # Alternative to manual HTTPS redirection
from functools import wraps

# Database (Example - Replace with your actual database setup)
# In a real application, use SQLAlchemy or another ORM
users = {
    "testuser": "password123"  # Insecure - Replace with hashed passwords!
}

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(24)

# HTTPS Enforcement (Manual)
@app.before_request
def before_request():
    """Redirect HTTP to HTTPS."""
    if not request.is_secure and app.env != "development":  # Don't redirect in development
        url = request.url
        parsed_url = urlparse(url)
        url = parsed_url._replace(scheme="https").geturl()
        return redirect(url, code=301)

# HTTPS Enforcement (Using Flask-SSLify - Alternative)
# sslify = SSLify(app) # Uncomment to use Flask-SSLify

# Session Cookie Configuration
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent client-side JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF (Lax or Strict)

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute"]  # Example: Allow 5 requests per minute
)

# Password Complexity Validator
def password_complexity(form, field):
    if not any(char.isdigit() for char in field.data):
        raise ValidationError('Password must contain at least one digit.')
    if not any(char.isupper() for char in field.data):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not any(char.islower() for char in field.data):
        raise ValidationError('Password must contain at least one lowercase letter.')
    if not any(char in "!@#$%^&*()" for char in field.data):
        raise ValidationError('Password must contain at least one special character.')

# Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25), Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only alphanumeric characters and underscores")])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8), password_complexity])
    submit = SubmitField('Login')

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route("/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # In a real application, compare against hashed passwords!
        if username in users and users[username] == password:
            session['username'] = username
            flash('Login successful!', 'success')
            app.logger.info(f"User {username} logged in successfully.") # Logging successful login
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            app.logger.warning(f"Failed login attempt for user {username}.") # Logging failed login
    return render_template("login.html", form=form)

@app.route("/dashboard")
@login_required
def dashboard():
    username = session['username']
    return render_template("dashboard.html", username=username)

@app.route("/logout")
@login_required
def logout():
    username = session['username']
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    app.logger.info(f"User {username} logged out.") # Logging logout
    return redirect(url_for('login'))

# Example route to demonstrate rate limiting
@app.route("/api/limited")
@limiter.limit("2 per minute")
def limited_api():
    return "This API endpoint is rate-limited."

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    app.logger.warning(f"404 error: {request.url}") # Logging 404 errors
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f"500 error: {e}") # Logging 500 errors
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    app.logger.warning(f"Rate limit exceeded for IP: {get_remote_address()}") # Logging rate limit events
    return "Rate limit exceeded. Please try again later.", 429

# Security Headers (Example - Use Flask-Talisman for more comprehensive setup)
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' # HSTS
    return response

# Templates (Example - Create these in a 'templates' folder)

# login.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    <form method="POST" action="/">
        {{ form.csrf_token }}
        <p>
            {{ form.username.label }}<br>
            {{ form.username(size=32) }}
            {% for error in form.username.errors %}
                <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>
            {{ form.password.label }}<br>
            {{ form.password(size=32) }}
            {% for error in form.password.errors %}
                <span style="color: red;">[{{ error }}]</span>
            {% endfor %}
        </p>
        <p>{{ form.submit() }}</p>
    </form>
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            <ul>
            {% for category, message in messages %}
                <li class="alert alert-{{ category }}">{{ message }}</li>
            {% endfor %}
            </ul>
        {% endif %}
    {% endwith %}
</body>
</html>
"""

# dashboard.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <h1>Dashboard</h1>
    <p>Welcome, {{ username }}!</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""

# 404.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The page you requested could not be found.</p>
</body>
</html>
"""

# 500.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>500 Internal Server Error</title>
</head>
<body>
    <h1>500 Internal Server Error</h1>
    <p>An internal server error occurred.</p>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True, ssl_context="adhoc") # Enable SSL for local testing

