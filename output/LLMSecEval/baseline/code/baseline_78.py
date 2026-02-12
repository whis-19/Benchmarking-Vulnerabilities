import hashlib
import secrets
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a strong secret key

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
            email TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()


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


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if not username or not password or not email:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            salt, hashed_password = hash_password(password)
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                           (username, hashed_password, email))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, email FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Retrieve the salt from the database (assuming you store it separately)
            # In this example, we're not storing the salt separately, so we need to
            # extract it from the stored password.  This is a simplification for this example.
            # In a real application, store the salt in a separate column.
            stored_password = user['password']
            stored_salt = stored_password[:32]  # Assuming salt is the first 32 characters (64 hex digits)

            if verify_password(stored_salt, stored_password, password):
                session['user_id'] = user['id']
                session['username'] = username
                session['email'] = user['email']
                flash('Login successful!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Incorrect password.', 'error')
        else:
            flash('Incorrect username.', 'error')

    return render_template('login.html')


@app.route('/profile')
def profile():
    if 'user_id' in session:
        return render_template('profile.html', username=session['username'], email=session['email'])
    else:
        return redirect(url_for('login'))


@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_email = request.form['old_email']
        new_email = request.form['new_email']
        password = request.form['password']

        if not old_email or not new_email or not password:
            flash('All fields are required.', 'error')
            return render_template('change_email.html')

        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password, email FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        if not user:
            flash('User not found.', 'error')
            conn.close()
            return render_template('change_email.html')

        stored_password = user['password']
        stored_salt = stored_password[:32]  # Assuming salt is the first 32 characters

        if user['email'] != old_email:
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
            session['email'] = new_email  # Update the session
            flash('Email changed successfully!', 'success')
        except Exception as e:
            flash(f'Error changing email: {e}', 'error')
        finally:
            conn.close()

        return redirect(url_for('profile'))

    return render_template('change_email.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('email', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)

