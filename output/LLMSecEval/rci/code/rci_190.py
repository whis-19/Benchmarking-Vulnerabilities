from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3
import os
import secrets  # For generating secure random numbers
import hashlib
import bcrypt  # For secure password hashing

app = Flask(__name__)

# Securely load the secret key from an environment variable
# Example:  export SECRET_KEY="your_random_secret_key"  (in your terminal)
#  or set it in your deployment environment (e.g., Heroku, AWS)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(24) # Generate a random key if not set

# Database initialization (simplified)
def init_db():
    conn = sqlite3.connect('users.db')
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

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Secure password hashing using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        try:
            # Use parameterized queries to prevent SQL injection
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password.decode('utf-8')))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # Use parameterized queries to prevent SQL injection
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            hashed_password = result[0]
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                # Secure session management using Flask's session object
                session['username'] = username
                return redirect(url_for('index')) # Redirect to a logged-in page
            else:
                return "Invalid credentials"
        else:
            return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove the username from the session
    return redirect(url_for('index'))

# Example of a protected route
@app.route('/profile')
def profile():
    if 'username' in session:
        return f"Welcome, {session['username']}!"
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

