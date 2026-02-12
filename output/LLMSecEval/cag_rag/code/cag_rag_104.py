import bcrypt
import sqlite3
import secrets
import os
from flask import Flask, request, render_template, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# Database setup (using SQLite for simplicity, consider PostgreSQL for production)
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Input Validation
def validate_username(username):
    if not (4 <= len(username) <= 20):
        return False, "Username must be between 4 and 20 characters."
    if not username.isalnum():
        return False, "Username must contain only alphanumeric characters."
    return True, None

def validate_password(password):
    if not (8 <= len(password) <= 64):
        return False, "Password must be between 8 and 64 characters."
    # Add more password complexity checks here if needed (e.g., require special characters, numbers)
    return True, None


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input validation
        username_valid, username_error = validate_username(username)
        password_valid, password_error = validate_password(password)

        if not username_valid:
            flash(username_error)
            return render_template('register.html')

        if not password_valid:
            flash(password_error)
            return render_template('register.html')

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                session['username'] = username
                flash('Login successful!')
                return redirect(url_for('home'))
            else:
                flash('Incorrect password.')
        else:
            flash('Incorrect username.')

    return render_template('login.html')


@app.route('/home')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))


@app.route('/')
def index():
    return redirect(url_for('home'))


if __name__ == '__main__':
    # Ensure the database file exists
    if not os.path.exists(DATABASE):
        init_db()

    app.run(debug=True)  # Disable debug mode in production

