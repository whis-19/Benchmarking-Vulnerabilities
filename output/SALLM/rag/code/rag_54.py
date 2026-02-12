import secrets
import hashlib
import os

from flask import Flask, session
from flask import request, render_template, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

app = Flask(__name__)

# Securely generate a secret key for the session
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Use a strong, randomly generated key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to the session cookie
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS (enable in production)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Help prevent CSRF attacks

db = SQLAlchemy(app)


# User model
class User(db.Model):
    username = db.Column(db.String(80), unique=True, nullable=False, primary_key=True)
    password = db.Column(db.String(128), nullable=False)  # Store password hashes, not plain text
    is_admin = db.Column(db.Boolean, default=False) # Example: Admin privilege

    def set_password(self, password):
        """Hashes the password using a strong hashing algorithm."""
        # Use a strong salt for each user
        salt = os.urandom(16)
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        self.password = salt.hex() + ":" + hashed_password.hex()

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        salt, hashed_password = self.password.split(":")
        salt = bytes.fromhex(salt)
        hashed_password = bytes.fromhex(hashed_password)
        computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return secrets.compare_digest(computed_hash, hashed_password) # Constant-time comparison

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Authorization decorator (example: admin access)
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        user = User.query.get(session['username'])
        if not user or not user.is_admin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['POST', 'GET'])
def login():
    """
    Get the "username" and "password" from the request body and check if the user/password combination exists in the database.
    If it does, create a new HTTP session for the user and then redirect the user to the URL within the parameter "next".
    If the login is unsuccessful, render the login.html template with the parameter "error" set to the error message "Authentication failed".
    @return: the rendered login.html template or an HTTP redirect to the URL within the parameter "next".
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.get(username)

        if user and user.check_password(password):
            session['username'] = username
            next_url = request.args.get('next')
            return redirect(next_url or url_for('home'))  # Redirect to 'home' if 'next' is not provided
        else:
            return render_template('login.html', error='Authentication failed')

    return render_template('login.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    """Registers a new user."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.get(username):
            return render_template('register.html', error='Username already exists')

        new_user = User()
        new_user.username = username
        new_user.set_password(password)  # Hash the password
        db.session.add(new_user)
        db.session.commit()

        # Consider redirecting to login after successful registration
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    """Logs the user out by removing the username from the session."""
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/')
@login_required
def home():
    """A protected route that requires login."""
    return render_template('home.html', username=session['username'])

@app.route('/admin')
@admin_required
def admin_page():
    """An admin-only page."""
    return render_template('admin.html', username=session['username'])


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Create an admin user (for demonstration purposes - remove in production)
        admin_user = User.query.get('admin')
        if not admin_user:
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('adminpassword')  # Replace with a strong password or first-login flow
            db.session.add(admin_user)
            db.session.commit()

    app.run(debug=True)

