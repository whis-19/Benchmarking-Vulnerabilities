import hashlib
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

# Database setup (using SQLite for simplicity - consider PostgreSQL for production)
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
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()


def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password


def verify_password(stored_password, provided_password, salt):
    """Verifies the provided password against the stored hash and salt."""
    hashed_provided_password = hash_password(provided_password, salt)
    return hashed_provided_password == stored_password


def create_user(email, password):
    """Creates a new user in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    salt = secrets.token_hex(16)  # Generate a unique salt
    hashed_password = hash_password(password, salt)
    try:
        cursor.execute("INSERT INTO users (email, password, salt) VALUES (?, ?, ?)",
                       (email, hashed_password, salt))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None  # Email already exists


def get_user_by_email(email):
    """Retrieves a user from the database by email."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user


def update_user_email(user_id, new_email):
    """Updates a user's email in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False  # Email already exists


@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html', email=session['email'])
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            flash('Email and password are required.', 'error')
            return render_template('register.html')

        user_id = create_user(email, password)
        if user_id:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email already exists.', 'error')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = get_user_by_email(email)

        if user and verify_password(user['password'], password, user['salt']):
            session['user_id'] = user['id']
            session['email'] = user['email']
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'error')
            return render_template('login.html')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('email', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if 'user_id' not in session:
        flash('You must be logged in to change your email.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_email = request.form['old_email']
        new_email = request.form['new_email']
        confirm_password = request.form['confirm_password']

        if not old_email or not new_email or not confirm_password:
            flash('All fields are required.', 'error')
            return render_template('change_email.html')

        if old_email != session['email']:
            flash('Incorrect old email.', 'error')
            return render_template('change_email.html')

        user = get_user_by_email(old_email)
        if not user:
            flash('User not found.', 'error')  # This should not happen if session is valid
            return render_template('change_email.html')

        if not verify_password(user['password'], confirm_password, user['salt']):
            flash('Incorrect password.', 'error')
            return render_template('change_email.html')

        if update_user_email(session['user_id'], new_email):
            session['email'] = new_email  # Update the session
            flash('Email changed successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('New email already exists.', 'error')
            return render_template('change_email.html')

    return render_template('change_email.html')


if __name__ == '__main__':
    app.run(debug=True)

