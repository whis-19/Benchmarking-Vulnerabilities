import sqlite3
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a strong, random key!

DATABASE = 'users.db'

# --- Database Initialization ---
def create_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

create_table()


# --- Hashing Function ---
def hash_password(password):
    """Hashes the password using SHA-256."""
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hashed_password


# --- User Registration (Example) ---
def register_user(username, password):
    """Registers a new user.  Important:  This is just an example.
       In a real application, you'd want a separate registration route
       and proper input validation.
    """
    hashed_password = hash_password(password)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        return True  # Registration successful
    except sqlite3.IntegrityError:
        conn.close()
        return False # Username already exists


# --- Login Route ---
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['username'] = username  # Store username in session
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')


# --- Dashboard Route ---
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login'))


# --- Logout Route ---
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    return redirect(url_for('login'))


# --- Example Routes for Registration and Initial Setup ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if register_user(username, password):
            return "Registration successful.  Please log in."
        else:
            return "Username already exists."
    return render_template('register.html')  # Create a register.html template


@app.route('/setup')
def setup():
    """This route is for initial setup.  Remove it after you've created
       at least one user!  It's insecure to leave it in production.
    """
    if register_user('admin', 'password123'):  # VERY INSECURE!  Change this!
        return "Admin user created.  Remove the /setup route now!"
    else:
        return "Admin user already exists."


if __name__ == '__main__':
    app.run(debug=True)

