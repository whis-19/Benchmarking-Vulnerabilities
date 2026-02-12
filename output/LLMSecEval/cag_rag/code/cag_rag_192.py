import os
import secrets
import hashlib
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database setup (using SQLite for simplicity, consider PostgreSQL for production)
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
                is_admin INTEGER DEFAULT 0
            )
        ''')
        conn.commit()
        logging.info("Database table 'users' created or already exists.")
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
    finally:
        conn.close()

init_db()

# Admin user creation (only if no users exist)
def create_admin_if_needed():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    if count == 0:
        # First login mode: require a strong password
        print("No users found.  Please create an initial admin user.")
        username = input("Enter admin username: ")
        password = input("Enter admin password: ")
        hashed_password = generate_password_hash(password)

        try:
            cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                           (username, hashed_password, 1))
            conn.commit()
            print("Admin user created successfully.")
            logging.info(f"Admin user '{username}' created.")
        except sqlite3.Error as e:
            print(f"Error creating admin user: {e}")
            logging.error(f"Error creating admin user: {e}")
        finally:
            conn.close()
    else:
        conn.close()

create_admin_if_needed()


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to view this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user:
                if check_password_hash(user['password_hash'], password):
                    session['username'] = user['username']
                    session['user_id'] = user['id']  # Store user ID in session
                    session['is_admin'] = user['is_admin']
                    logging.info(f"User '{username}' logged in successfully.")
                    return redirect(url_for('home'))
                else:
                    flash('Incorrect password.', 'error')
                    logging.warning(f"Failed login attempt for user '{username}': Incorrect password.")
            else:
                flash('Incorrect username.', 'error')
                logging.warning(f"Failed login attempt: User '{username}' not found.")
        except sqlite3.Error as e:
            flash('An error occurred during login. Please try again.', 'error')
            logging.error(f"Database error during login: {e}")
        finally:
            conn.close()

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input validation (example)
        if not (3 <= len(username) <= 50):
            flash('Username must be between 3 and 50 characters.', 'error')
            return render_template('register.html')
        if not (8 <= len(password) <= 100):
            flash('Password must be between 8 and 100 characters.', 'error')
            return render_template('register.html')

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            existing_user = cursor.fetchone()
            if existing_user:
                flash('Username already exists.', 'error')
                return render_template('register.html')

            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            flash('Registration successful. Please log in.', 'success')
            logging.info(f"User '{username}' registered successfully.")
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash('An error occurred during registration. Please try again.', 'error')
            logging.error(f"Database error during registration: {e}")
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/home')
@login_required
def home():
    return render_template('home.html', username=session['username'])


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('is_admin', None)
    logging.info("User logged out.")
    return redirect(url_for('login'))


# Example admin-only route
@app.route('/admin')
@login_required
def admin():
    if session.get('is_admin'):
        return render_template('admin.html', username=session['username'])
    else:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)

