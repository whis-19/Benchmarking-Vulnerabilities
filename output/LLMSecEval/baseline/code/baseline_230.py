import os
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for session management

# Database setup (using SQLite for simplicity)
DATABASE = 'users.db'

def get_db_connection():
    """Connects to the database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn

def init_db():
    """Initializes the database (creates the users table if it doesn't exist)."""
    conn = get_db_connection()
    with conn:  # Use 'with' for automatic commit/rollback
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
    conn.close()

# Call init_db when the app starts
with app.app_context():
    init_db()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required.')
            return render_template('register.html')

        try:
            conn = get_db_connection()
            with conn:
                # Hash the password before storing it
                password_hash = generate_password_hash(password)

                # Insert the username and password hash into the database
                conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                             (username, password_hash))

                flash('Registration successful! Please log in.')
                return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different username.')
            return render_template('register.html')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            result = cur.fetchone()

            if result:
                password_hash = result['password_hash']  # Access by column name
                if check_password_hash(password_hash, password):
                    flash('Login successful!')
                    # In a real application, you would set a session cookie here
                    # to track the logged-in user.  For example:
                    # session['username'] = username
                    return redirect(url_for('index'))  # Redirect to a logged-in area
                else:
                    flash('Incorrect password.')
            else:
                flash('Username not found.')
        finally:
            conn.close()

    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)

