import os
import secrets
from functools import wraps
from flask import Flask, render_template, session, redirect, url_for, request, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import hashlib
from flask_csp import CSP
from flask_wtf.csrf import CSRFProtect, generate_csrf

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a strong secret key
app.config['DATABASE'] = 'users.db'
app.config['CSP_POLICY'] = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'frame-ancestors': '\'none\'', # Prevent clickjacking
}

csp = CSP(app)
csrf = CSRFProtect(app)

# Initialize the database
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def create_user(username, password, email, ssn_last_4):
    """Creates a new user in the database."""
    db = get_db()
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), os.urandom(16), 100000)
    try:
        db.execute(
            "INSERT INTO users (username, password, email, ssn_last_4) VALUES (?, ?, ?, ?)",
            (username, hashed_password, email, ssn_last_4),
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists

def authenticate_user(username, password):
    """Authenticates a user against the database."""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user:
        hashed_password = user['password']
        if hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), os.urandom(16), 100000) == hashed_password:
            return user
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        ssn_last_4 = request.form['ssn_last_4']

        if not (username and password and email and ssn_last_4):
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if create_user(username, password, email, ssn_last_4):
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose a different one.', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = authenticate_user(username, password)

        if user:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('info'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/info')
@login_required
def info():
    db = get_db()
    user_id = session['user_id']
    user = db.execute("SELECT username, email, ssn_last_4 FROM users WHERE id = ?", (user_id,)).fetchone()

    if user:
        # Escape user data before rendering to prevent XSS
        username = escape(user['username'])
        email = escape(user['email'])
        ssn_last_4 = escape(user['ssn_last_4'])
        csrf_token = generate_csrf()
        return render_template('info.html', username=username, email=email, ssn_last_4=ssn_last_4, csrf_token=csrf_token)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

def escape(data):
    """Simple HTML escaping function."""
    return str(data).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/')
def index():
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Check if the database exists, and if not, initialize it.
    if not os.path.exists(app.config['DATABASE']):
        init_db()
    app.run(debug=True)

