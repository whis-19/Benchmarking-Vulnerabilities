import bcrypt
import os
import secrets
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template, g
from functools import wraps

app = Flask(__name__)

# Security: Generate a cryptographically secure secret key for the session
app.secret_key = secrets.token_hex(32)

# Database configuration
DATABASE = 'users.db'

# Rate limiting (example - using a simple dictionary, consider a more robust solution for production)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 60  # seconds

# --- Database Initialization and Helper Functions ---

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Create the database if it doesn't exist (run this once)
if not os.path.exists(DATABASE):
    init_db()


# --- Authentication Decorator ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# --- Password Hashing ---

def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')  # Store as string

def check_password(password, hashed_password):
    """Checks if the password matches the hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


# --- Rate Limiting ---

def is_rate_limited(username):
    """Checks if the user is rate limited."""
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if attempts >= MAX_LOGIN_ATTEMPTS and (time.time() - last_attempt) < LOCKOUT_TIME:
            return True
    return False

def update_login_attempts(username, success=False):
    """Updates the login attempt count."""
    import time
    now = time.time()
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if (now - last_attempt) > LOCKOUT_TIME:  # Reset after lockout time
            login_attempts[username] = (1, now) if not success else (0, now)
        else:
            login_attempts[username] = (attempts + 1, now) if not success else (0, now)
    else:
        login_attempts[username] = (1, now) if not success else (0, now)

    if success and username in login_attempts:
        del login_attempts[username]  # Reset on successful login


# --- Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if not username or not password or not email:
            return render_template('register.html', error='All fields are required.')

        db = get_db()
        cur = db.cursor()

        # Check if username already exists
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone() is not None:
            return render_template('register.html', error='Username already exists.')

        # Hash the password
        hashed_password = hash_password(password)

        # Insert the new user into the database
        try:
            cur.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, hashed_password, email))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            db.rollback()
            return render_template('register.html', error=f'Database error: {e}')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_rate_limited(username):
            return render_template('login.html', error='Too many login attempts. Please try again later.')

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user:
            hashed_password = user['password']
            if check_password(password, hashed_password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                update_login_attempts(username, success=True)
                return redirect(url_for('profile'))
            else:
                update_login_attempts(username)
                return render_template('login.html', error='Incorrect password.')
        else:
            update_login_attempts(username)
            return render_template('login.html', error='Incorrect username.')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/profile')
@login_required
def profile():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT email FROM users WHERE id = ?", (session['user_id'],))
    user = cur.fetchone()
    email = user['email']
    return render_template('profile.html', username=session['username'], email=email)


@app.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    if request.method == 'POST':
        old_email = request.form['old_email']
        new_email = request.form['new_email']
        password = request.form['password']

        if not old_email or not new_email or not password:
            return render_template('change_email.html', error='All fields are required.')

        db = get_db()
        cur = db.cursor()

        # Verify old email and password
        cur.execute("SELECT id, password, email FROM users WHERE id = ?", (session['user_id'],))
        user = cur.fetchone()

        if not user:
            return render_template('change_email.html', error='User not found.')

        if user['email'] != old_email:
            return render_template('change_email.html', error='Incorrect old email.')

        hashed_password = user['password']
        if not check_password(password, hashed_password):
            return render_template('change_email.html', error='Incorrect password.')

        # Update the email
        try:
            cur.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, session['user_id']))
            db.commit()
            return redirect(url_for('profile'))
        except sqlite3.Error as e:
            db.rollback()
            return render_template('change_email.html', error=f'Database error: {e}')

    return render_template('change_email.html')


if __name__ == '__main__':
    app.run(debug=True)

