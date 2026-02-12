import sqlite3
from flask import Flask, request, redirect, url_for, render_template, g
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Database Configuration
DATABASE = 'users.db'  # Store the database file in the same directory as the script
app.config['DATABASE'] = DATABASE
SECRET_KEY = os.urandom(24)  # Generate a random secret key for session management
app.secret_key = SECRET_KEY

# Initialize the database (create table if it doesn't exist)
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Get database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row  # Return rows as dictionaries
    return db

# Close database connection after each request
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Create the database schema (schema.sql)
# This file should be in the same directory as the Python script
# Example schema.sql:
# CREATE TABLE IF NOT EXISTS users (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     username TEXT UNIQUE NOT NULL,
#     password TEXT NOT NULL
# );

# Function to create a new user (for initial setup)
def create_user(username, password):
    db = get_db()
    hashed_password = generate_password_hash(password)
    try:
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        # Username already exists
        return False

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cur = db.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cur.fetchone()

        if row:
            hashed_password = row['password']
            if check_password_hash(hashed_password, password):
                # Authentication successful
                return redirect(url_for('success'))
            else:
                # Incorrect password
                return redirect(url_for('cant_login'))
        else:
            # User not found
            return redirect(url_for('cant_login'))

    return render_template('login.html')  # Create a login.html template

# Success route
@app.route('/success')
def success():
    return "Login successful!"  # Replace with your actual success page

# Cannot login route
@app.route('/cant_login')
def cant_login():
    return "Login failed. Invalid username or password."  # Replace with a user-friendly error message

# Internal server error route
@app.route('/internal_server_error')
def internal_server_error():
    return "Internal server error."  # Replace with a user-friendly error message

# Error handling (example)
@app.errorhandler(500)
def internal_server_error_handler(e):
    return redirect(url_for('internal_server_error'))

if __name__ == '__main__':
    # Initialize the database if it doesn't exist
    if not os.path.exists(DATABASE):
        init_db()
        # Create an initial user (for testing purposes)
        # IMPORTANT: Remove this in a production environment!
        create_user("testuser", "password123")  # Replace with a strong password

    app.run(debug=True) # Set debug=False in production

