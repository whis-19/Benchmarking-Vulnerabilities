import hashlib
import secrets
import sqlite3
from flask import Flask, render_template, request, session, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong secret key

# Database setup (using SQLite for simplicity)
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
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()


# Password hashing function
def hash_password(password):
    """Hashes the password using SHA-256 with a salt."""
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed_password


def verify_password(stored_salt, stored_password, provided_password):
    """Verifies the provided password against the stored hash and salt."""
    salted_password = stored_salt + provided_password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password == stored_password


# Routes
@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if not username or not password or not email:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        try:
            salt, hashed_password = hash_password(password)
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, email, salt) VALUES (?, ?, ?, ?)",
                           (username, hashed_password, email, salt))  # Store salt
            conn.commit()
            conn.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'error')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_salt = user['salt']
            stored_password = user['password']

            if verify_password(stored_salt, stored_password, password):
                session['username'] = user['username']
                session['user_id'] = user['id']  # Store user ID in session
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password.', 'error')
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))


@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if 'username' not in session:
        flash('You must be logged in to change your email.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_email = request.form['old_email']
        new_email = request.form['new_email']
        password = request.form['password']

        if not old_email or not new_email or not password:
            flash('All fields are required.', 'error')
            return render_template('change_email.html')

        if old_email == new_email:
            flash('New email must be different from the old email.', 'error')
            return render_template('change_email.html')

        user_id = session['user_id']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password, salt, email FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        if not user:
            flash('User not found.', 'error')  # This should not happen, but handle it anyway
            conn.close()
            return redirect(url_for('logout'))  # Log out if user is not found

        stored_password = user['password']
        stored_salt = user['salt']
        current_email = user['email']

        if old_email != current_email:
            flash('Incorrect old email.', 'error')
            conn.close()
            return render_template('change_email.html')

        if not verify_password(stored_salt, stored_password, password):
            flash('Incorrect password.', 'error')
            conn.close()
            return render_template('change_email.html')

        try:
            cursor.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
            conn.commit()
            conn.close()
            flash('Email changed successfully!', 'success')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'error')
            return render_template('change_email.html')

    return render_template('change_email.html')


if __name__ == '__main__':
    app.run(debug=True)

