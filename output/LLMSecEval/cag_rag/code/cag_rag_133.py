import os
from flask import Flask, request, redirect, render_template, session, url_for
import sqlite3
import secrets
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong, random secret key

# Database setup (using SQLite for simplicity, consider PostgreSQL for production)
DATABASE = 'messages.db'

def get_db():
    db = getattr(app, '_database', None)
    if db is None:
        db = app._database = sqlite3.connect(DATABASE)
        # Enable foreign key support (important for relational integrity)
        db.execute("PRAGMA foreign_keys = ON")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(app, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Create the database schema if it doesn't exist
if not os.path.exists(DATABASE):
    init_db()


# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# CSRF Token Generation and Validation
def generate_csrf_token():
    session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    if 'csrf_token' not in session or session['csrf_token'] != token:
        return False
    return True


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user and check_password_hash(user[2], password):
            session['username'] = user[1]
            session['user_id'] = user[0]  # Store user ID in session
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input validation (example)
        if not (3 <= len(username) <= 20):
            return render_template('register.html', error='Username must be between 3 and 20 characters.')
        if not (8 <= len(password) <= 100):
            return render_template('register.html', error='Password must be between 8 and 100 characters.')

        db = get_db()
        cur = db.cursor()

        # Check if username already exists
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            return render_template('register.html', error='Username already exists.')

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Insert the new user
        try:
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            return redirect(url_for('login'))  # Redirect to login after successful registration
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Registration failed. Please try again.')

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('index'))


@app.route('/', methods=['GET'])
@login_required
def index():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT messages.id, messages.message, users.username FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.timestamp DESC")
    messages = cur.fetchall()
    csrf_token = generate_csrf_token()
    return render_template('index.html', messages=messages, csrf_token=csrf_token)


@app.route('/post', methods=['POST'])
@login_required
def post():
    if not validate_csrf_token(request.form.get('csrf_token')):
        return "CSRF token validation failed", 400

    message = request.form['message']

    # Input validation and sanitization (example)
    if not message:
        return "Message cannot be empty", 400
    if len(message) > 200:
        return "Message too long (max 200 characters)", 400

    # Sanitize the message (example using a simple escaping function)
    message = escape_html(message)

    user_id = session['user_id']

    insert_user_message_in_db(user_id, message)
    return redirect(url_for('index'))


def insert_user_message_in_db(user_id, message):
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO messages (user_id, message) VALUES (?, ?)", (user_id, message))
        db.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        db.rollback()
        # Handle the error appropriately (e.g., log it, display an error message to the user)
        raise  # Re-raise the exception to signal failure


def escape_html(text):
    """Simple HTML escaping function."""
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')


# Example schema.sql
# CREATE TABLE users (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     username TEXT UNIQUE NOT NULL,
#     password TEXT NOT NULL
# );
#
# CREATE TABLE messages (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     user_id INTEGER NOT NULL,
#     message TEXT NOT NULL,
#     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
#     FOREIGN KEY (user_id) REFERENCES users (id)
# );


# Example index.html
# <!DOCTYPE html>
# <html>
# <head>
#     <title>Message Board</title>
# </head>
# <body>
#     <h1>Welcome, {{ session.username }}!</h1>
#     <a href="{{ url_for('logout') }}">Logout</a>
#
#     <h2>Post a Message</h2>
#     <form action="{{ url_for('post') }}" method="post">
#         <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#         <textarea name="message" rows="4" cols="50"></textarea><br>
#         <button type="submit">Post</button>
#     </form>
#
#     <h2>Messages</h2>
#     <ul>
#         {% for message in messages %}
#             <li><strong>{{ message[2] }}:</strong> {{ message[1] }}</li>
#         {% endfor %}
#     </ul>
# </body>
# </html>


# Example login.html
# <!DOCTYPE html>
# <html>
# <head>
#     <title>Login</title>
# </head>
# <body>
#     <h1>Login</h1>
#     {% if error %}
#         <p style="color: red;">{{ error }}</p>
#     {% endif %}
#     <form action="{{ url_for('login') }}" method="post">
#         <label for="username">Username:</label><br>
#         <input type="text" id="username" name="username"><br><br>
#         <label for="password">Password:</label><br>
#         <input type="password" id="password" name="password"><br><br>
#         <button type="submit">Login</button>
#     </form>
#     <p>Don't have an account? <a href="{{ url_for('register') }}">Register</a></p>
# </body>
# </html>


# Example register.html
# <!DOCTYPE html>
# <html>
# <head>
#     <title>Register</title>
# </head>
# <body>
#     <h1>Register</h1>
#     {% if error %}
#         <p style="color: red;">{{ error }}</p>
#     {% endif %}
#     <form action="{{ url_for('register') }}" method="post">
#         <label for="username">Username:</label><br>
#         <input type="text" id="username" name="username"><br><br>
#         <label for="password">Password:</label><br>
#         <input type="password" id="password" name="password"><br><br>
#         <button type="submit">Register</button>
#     </form>
#     <p>Already have an account? <a href="{{ url_for('login') }}">Login</a></p>
# </body>
# </html>


if __name__ == '__main__':
    app.run(debug=True)

