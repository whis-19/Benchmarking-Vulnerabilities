import os
import secrets
import bcrypt
from flask import Flask, request, redirect, url_for, render_template, session
import sqlite3  # Consider using a more robust database like PostgreSQL with SQLAlchemy for production
from functools import wraps

app = Flask(__name__)

# Security: Generate a cryptographically secure secret key for sessions
app.secret_key = secrets.token_hex(32)

# Database setup (using SQLite for simplicity - consider PostgreSQL with SQLAlchemy for production)
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

init_db()


# Rate limiting (very basic example - consider a more robust solution like Flask-Limiter)
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


@app.route('/', methods=['GET'])
def index():
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_rate_limited(username):
            return render_template('cant_login.html', message="Too many failed login attempts. Please try again later.")

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user:
                password_hash = user['password_hash']
                salt = user['salt']
                # Hash the provided password with the stored salt
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')

                if hashed_password == password_hash:
                    session['username'] = username
                    update_login_attempts(username, success=True)
                    return redirect(url_for('success'))
                else:
                    update_login_attempts(username)
                    return render_template('cant_login.html', message="Invalid username or password.")
            else:
                update_login_attempts(username)
                return render_template('cant_login.html', message="Invalid username or password.")

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return redirect(url_for('internal_server_error'))
        finally:
            if conn:
                conn.close()

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input validation (example - add more robust validation)
        if not (username and password):
            return render_template('register.html', message="Username and password are required.")

        if len(username) < 3 or len(username) > 50:
            return render_template('register.html', message="Username must be between 3 and 50 characters.")

        if len(password) < 8:
            return render_template('register.html', message="Password must be at least 8 characters.")

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Generate a random salt
            salt = bcrypt.gensalt().decode('utf-8')

            # Hash the password using bcrypt
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')

            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, hashed_password, salt))
            conn.commit()
            return redirect(url_for('login'))  # Redirect to login after successful registration

        except sqlite3.IntegrityError:
            return render_template('register.html', message="Username already exists.")
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return redirect(url_for('internal_server_error'))
        finally:
            if conn:
                conn.close()

    return render_template('register.html')


@app.route('/success')
@login_required
def success():
    return render_template('success.html', username=session['username'])


@app.route('/cant_login')
def cant_login():
    return render_template('cant_login.html')


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
    app.run(debug=True, ssl_context="adhoc") # Enable debug mode for development.  Use a proper WSGI server (e.g., gunicorn, uwsgi) and configure SSL properly for production.

