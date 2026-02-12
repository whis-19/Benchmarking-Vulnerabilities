import os
from flask import Flask, session, render_template, redirect, url_for, request, flash
from functools import wraps
import secrets
import configparser  # For reading configuration files
import bcrypt  # For password hashing
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape  # For escaping user input

app = Flask(__name__)

# Configuration - Load from environment variables
# Prioritize environment variables, fall back to config.ini if not found
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# Session configuration (important for security)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS (enable when deploying with HTTPS)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['SESSION_REFRESH_EACH_REQUEST'] = True # Refresh session on each request

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"],  # Adjust limits as needed
    storage_uri="memory://"  # Use a persistent storage for production
)

# User authentication data (loaded from database - example using a dictionary)
# In a real application, use a database like PostgreSQL or MySQL
# and an ORM like SQLAlchemy
users = {
    'user1': {'hashed_password': bcrypt.hashpw('password123'.encode('utf-8'), bcrypt.gensalt()), 'email': 'user1@example.com'},
    'user2': {'hashed_password': bcrypt.hashpw('securepassword'.encode('utf-8'), bcrypt.gensalt()), 'email': 'user2@example.com'}
}

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input Validation
        if not (4 <= len(username) <= 50 and 8 <= len(password) <= 100):  # Example length constraints
            flash('Invalid username or password format.', 'error')
            return render_template('login.html')

        # Proper input validation is crucial to prevent SQL injection attacks, where malicious code is injected into database queries.
        if username in users:
            hashed_password = users[username]['hashed_password']
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('info'))
            else:
                flash('Invalid username or password.', 'error')  # Generic error message
        else:
            flash('Invalid username or password.', 'error')  # Generic error message

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/info')
@login_required
def info():
    username = session['username']
    email = users[username]['email']  # Get email from user data
    # Escape the username and email before rendering in the template to prevent XSS
    escaped_username = escape(username)
    escaped_email = escape(email)
    return render_template('info.html', username=escaped_username, email=escaped_email)


# Example of handling errors
@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Too many requests. Please try again later.", "error")
    return render_template("login.html"), 429

# Next Steps (Critical):
# 1. Implement a Database: Replace the `users` dictionary with a connection to a real database (e.g., PostgreSQL, MySQL).  Use SQLAlchemy to interact with the database securely.  Store password hashes in a separate table.
# 2. CSRF Protection: Implement CSRF protection using `Flask-WTF`.  CSRF (Cross-Site Request Forgery) attacks trick users into performing actions they didn't intend to. Flask-WTF provides protection against this.
# 3. HTTPS: Configure HTTPS on your web server.  This is *mandatory* for production deployments.  Without HTTPS, your application is vulnerable to session hijacking and other attacks.
# 4. More Robust Input Validation: Implement more comprehensive input validation, including checking for invalid characters and other potential vulnerabilities.  Consider using a library like `WTForms` to simplify input validation.
# 5. Persistent Rate Limiter Storage: Configure `Flask-Limiter` to use a persistent storage like Redis or Memcached for production deployments.
# 6. Security Testing: Thoroughly test your application for security vulnerabilities.  Consider using a web application security scanner.
# 7. Password Complexity Policy: Implement a password complexity policy and a password strength meter.
# 8. Regularly Rotate Session Keys: Consider periodically rotating the `app.secret_key` to invalidate existing sessions.
# 9. Logging and Auditing: Implement comprehensive logging and auditing to track user activity and detect potential security breaches.
# 10. Content Security Policy (CSP): Implement a Content Security Policy to further mitigate XSS attacks. CSP allows you to define which sources of content (scripts, stylesheets, images, etc.) are allowed to be loaded by the browser.
# 11. Subresource Integrity (SRI): If using CDNs, implement Subresource Integrity to ensure the integrity of the loaded files.
# 12. Two-Factor Authentication (2FA): For high-security applications, consider implementing two-factor authentication.
# 13. Regular Security Audits: Conduct regular security audits and penetration testing to identify and address vulnerabilities.

