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
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()


# Password hashing function (using salt for security)
def hash_password(password, salt):
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password


# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if username or email already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('Username already exists.', 'error')
            conn.close()
            return render_template('register.html')

        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            flash('Email already exists.', 'error')
            conn.close()
            return render_template('register.html')

        # Generate a random salt
        salt = secrets.token_hex(16)

        # Hash the password with the salt
        hashed_password = hash_password(password, salt)

        try:
            cursor.execute("INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)",
                           (username, email, hashed_password, salt))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f'Database error: {e}', 'error')
        finally:
            conn.close()

    return render_template('register.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Verify the password
            salt = user['salt']
            hashed_password = hash_password(password, salt)

            if hashed_password == user['password']:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']  # Store email in session
                flash('Login successful!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Incorrect password.', 'error')
        else:
            flash('User not found.', 'error')

    return render_template('login.html')


# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('email', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


# Profile route (requires login)
@app.route('/profile')
def profile():
    if 'user_id' in session:
        return render_template('profile.html', username=session['username'], email=session['email'])
    else:
        flash('Please log in to view your profile.', 'info')
        return redirect(url_for('login'))


# Change Email Route
@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if 'user_id' not in session:
        flash('Please log in to change your email.', 'info')
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

        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify password
        cursor.execute("SELECT password, salt FROM users WHERE id = ?", (session['user_id'],))
        user_data = cursor.fetchone()

        if not user_data:
            flash('User not found.', 'error')  # This should not happen, but handle it anyway
            conn.close()
            return render_template('change_email.html')

        salt = user_data['salt']
        hashed_password = hash_password(confirm_password, salt)

        if hashed_password != user_data['password']:
            flash('Incorrect password.', 'error')
            conn.close()
            return render_template('change_email.html')

        # Check if the new email already exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (new_email,))
        if cursor.fetchone():
            flash('New email already exists.', 'error')
            conn.close()
            return render_template('change_email.html')

        # Update the email
        try:
            cursor.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, session['user_id']))
            conn.commit()
            session['email'] = new_email  # Update the email in the session
            flash('Email changed successfully!', 'success')
            return redirect(url_for('profile'))
        except sqlite3.Error as e:
            flash(f'Database error: {e}', 'error')
        finally:
            conn.close()

    return render_template('change_email.html')


# Routes for rendering templates
@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)

