import os
import hashlib
import secrets
import sqlite3
from flask import Flask, request, redirect, url_for, render_template, session
from functools import wraps
import configparser

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

# Configuration loading
config = configparser.ConfigParser()
config.read('config.ini')  # Store database path and other sensitive info in config.ini

DATABASE = config['database']['path']  # Path to the SQLite database
ADMIN_USERNAME = config['admin']['username']
ADMIN_PASSWORD_HASH = config['admin']['password_hash'] # Store the admin password hash in the config file

# Ensure the config file exists and has the necessary sections
if not os.path.exists('config.ini'):
    print("Error: config.ini not found.  Please create it with the necessary sections (database, admin).")
    exit()

# Database initialization (run only once)
def init_db():
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        ''')
        db.commit()

        # Check if the admin user exists. If not, create it.
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (ADMIN_USERNAME,))
        if cursor.fetchone()[0] == 0:
            # Generate a salt and hash the admin password
            salt = secrets.token_hex(16)
            hashed_password = hashlib.pbkdf2_hmac('sha256', ADMIN_PASSWORD_HASH.encode('utf-8'), salt.encode('utf-8'), 100000)
            hashed_password_hex = hashed_password.hex()

            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (ADMIN_USERNAME, hashed_password_hex, salt))
            db.commit()
            print("Admin user created.")


init_db()


# Password hashing function
def hash_password(password, salt):
    """Hashes the password using PBKDF2-HMAC with a salt."""
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return hashed_password.hex()


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            with sqlite3.connect(DATABASE) as db:
                cursor = db.cursor()
                cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()

                if result:
                    stored_password_hash, salt = result
                    hashed_password = hash_password(password, salt)

                    if hashed_password == stored_password_hash:
                        session['username'] = username
                        return redirect(url_for('success'))
                    else:
                        return redirect(url_for('cant_login'))
                else:
                    return redirect(url_for('cant_login'))

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return redirect(url_for('internal_server_error'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate password strength (example)
        if len(password) < 8:
            return render_template('register.html', error="Password must be at least 8 characters long.")

        try:
            with sqlite3.connect(DATABASE) as db:
                cursor = db.cursor()

                # Check if the username already exists
                cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
                if cursor.fetchone()[0] > 0:
                    return render_template('register.html', error="Username already exists.")

                # Generate a salt
                salt = secrets.token_hex(16)

                # Hash the password
                hashed_password = hash_password(password, salt)

                # Insert the user into the database
                cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, hashed_password, salt))
                db.commit()

                return redirect(url_for('login'))  # Redirect to login after successful registration

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return redirect(url_for('internal_server_error'))

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
    app.run(debug=True)

