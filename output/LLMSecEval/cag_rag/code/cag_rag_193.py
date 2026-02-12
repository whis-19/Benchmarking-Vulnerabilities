import os
import secrets
import bcrypt
from flask import Flask, request, redirect, url_for, render_template, session
import sqlite3  # Consider using a more robust database like PostgreSQL with SQLAlchemy for production
from functools import wraps

app = Flask(__name__)

# Security: Generate a cryptographically secure secret key for sessions
app.secret_key = secrets.token_hex(32)

# Database setup (using SQLite for simplicity - consider PostgreSQL for production)
DATABASE = 'users.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Access columns by name
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
        db.close()

# Create the database and table if they don't exist
try:
    init_db()
except sqlite3.OperationalError:
    # Database already exists
    pass


# Rate limiting (very basic - consider a more robust solution like Flask-Limiter)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

def is_rate_limited(username):
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if attempts >= MAX_LOGIN_ATTEMPTS and (time.time() - last_attempt) < LOCKOUT_DURATION:
            return True
    return False

def update_login_attempts(username, success=False):
    import time
    now = time.time()
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if (now - last_attempt) > LOCKOUT_DURATION:
            login_attempts[username] = (1, now)  # Reset after lockout
        else:
            login_attempts[username] = (attempts + 1, now)
    else:
        login_attempts[username] = (1, now)

    if success and username in login_attempts:
        del login_attempts[username]  # Reset on successful login


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_rate_limited(username):
            return render_template('cant_login.html', message="Too many failed login attempts. Please try again later.")

        try:
            db = get_db()
            cur = db.cursor()

            # Security: Use parameterized query to prevent SQL injection
            cur.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
            db.close()

            if user:
                password_hash = user['password_hash']

                # Security: Use bcrypt to compare password hashes
                if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                    # Authentication successful
                    session['username'] = username
                    update_login_attempts(username, success=True)
                    return redirect(url_for('success'))
                else:
                    # Authentication failed
                    update_login_attempts(username)
                    return redirect(url_for('cant_login'))
            else:
                # User not found
                update_login_attempts(username)
                return redirect(url_for('cant_login'))

        except Exception as e:
            print(f"Error during login: {e}")
            return redirect(url_for('internal_server_error'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input validation (basic example - expand as needed)
        if not (3 <= len(username) <= 20 and 8 <= len(password) <= 100):
            return render_template('register.html', error="Invalid username or password length.")

        try:
            db = get_db()
            cur = db.cursor()

            # Check if username already exists
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            existing_user = cur.fetchone()
            if existing_user:
                db.close()
                return render_template('register.html', error="Username already exists.")

            # Security: Hash the password using bcrypt
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Security: Use parameterized query to prevent SQL injection
            cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            db.close()

            return redirect(url_for('login'))  # Redirect to login after successful registration

        except Exception as e:
            print(f"Error during registration: {e}")
            return redirect(url_for('internal_server_error'))

    return render_template('register.html')


@app.route('/success')
@login_required
def success():
    return render_template('success.html', username=session['username'])


@app.route('/cant_login')
def cant_login():
    return render_template('cant_login.html', message="Invalid username or password.")


@app.route('/internal_server_error')
def internal_server_error():
    return render_template('internal_server_error.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    import time
    app.run(debug=True)

