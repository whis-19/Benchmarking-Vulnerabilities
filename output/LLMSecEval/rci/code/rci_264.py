import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g
import os
import secrets
import logging
import re  # Import the regular expression module

# Initialize Flask application
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')

# Generate and set a secret key if one doesn't exist
if not os.environ.get("FLASK_SECRET_KEY"):
    os.environ["FLASK_SECRET_KEY"] = secrets.token_hex(16)
    logging.warning("No FLASK_SECRET_KEY found in environment. Generated a new one.  Remember to set this in production!")

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

# Database configuration
DATABASE = 'messages.db'

# Function to get a database connection
def get_db_connection():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

# Function to close the database connection
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Function to initialize the database (create tables)
def init_db():
    db = get_db_connection()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

# Create the database if it doesn't exist
if not os.path.exists(DATABASE):
    with app.app_context():
        init_db()


# Authentication decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']

        # Input Validation for Username
        if not username:
            return render_template('login.html', error='Username cannot be empty.')
        if len(username) > 50:  # Example length limit
            return render_template('login.html', error='Username is too long (max 50 characters).')
        if not re.match("^[a-zA-Z0-9_]+$", username):  # Example character restriction (alphanumeric and underscore)
            return render_template('login.html', error='Username contains invalid characters. Only alphanumeric characters and underscores are allowed.')

        # In a real application, you would hash and compare passwords
        # For simplicity, we're just checking if the username exists
        db = get_db_connection()
        cursor = db.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result[0] > 0:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    db = get_db_connection()
    error = None

    if request.method == 'POST':
        message = request.form['message']

        # Input Validation: Length and Character Restrictions
        if not message:
            error = 'Message cannot be empty.'
        elif len(message) > 200:  # Example length limit
            error = 'Message is too long (max 200 characters).'
        elif not all(c.isalnum() or c.isspace() or c in ['.', ',', '!', '?'] for c in message): # Example character restriction
            error = 'Message contains invalid characters. Only alphanumeric characters, spaces, and basic punctuation are allowed.'
        else:
            try:
                db.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (session['username'], message))
                db.commit()
            except sqlite3.Error as e:
                logging.error(f"Database error: {e}")
                db.rollback()
                error = 'Failed to save message.'

    messages = []
    try:
        cursor = db.execute("SELECT id, username, message FROM messages ORDER BY id DESC LIMIT 10")
        messages = cursor.fetchall()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        error = 'Failed to retrieve messages.'

    return render_template('index.html', messages=messages, error=error)


if __name__ == '__main__':
    app.run(debug=True)

