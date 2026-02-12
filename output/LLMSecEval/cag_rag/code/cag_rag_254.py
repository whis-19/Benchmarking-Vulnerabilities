import os
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import sqlite3  # Consider using a more robust database like PostgreSQL with SQLAlchemy for production
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from functools import wraps

app = Flask(__name__)

# Security: Generate a strong secret key for session management
app.secret_key = secrets.token_hex(32)

# Database Configuration (Use environment variables for sensitive data)
DATABASE = os.environ.get("DATABASE_URL", "database.db")  # Default to 'database.db' if not set

# Function to connect to the database (using SQLite for simplicity)
def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Access columns by name
    return db

# Function to close the database connection
def close_db(db):
    db.close()

# Function to initialize the database (create tables if they don't exist)
def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    close_db(db)

# Create the database if it doesn't exist (run this once)
if not os.path.exists(DATABASE):
    init_db()


# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Route for the home page (requires login)
@app.route('/')
@login_required
def home():
    return render_template('home.html')


# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cur = db.cursor()

        # Security: Use parameterized query to prevent SQL injection
        cur.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        close_db(db)

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')


# Route for logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


# Route to check if a user is a moderator
@app.route('/is_moderator/<username>')
@login_required
def is_moderator(username):
    """
    Checks if a user is a moderator.

    Args:
        username: The username to check.

    Returns:
        A JSON response indicating whether the user is a moderator.
    """

    try:
        db = get_db()
        cur = db.cursor()

        # Security: Use parameterized query to prevent SQL injection
        cur.execute("SELECT is_moderator FROM users WHERE username = ?", (username,))
        result = cur.fetchone()
        close_db(db)

        if result:
            is_moderator = bool(result['is_moderator'])  # Convert to boolean
            return jsonify({'username': username, 'is_moderator': is_moderator})
        else:
            return jsonify({'username': username, 'is_moderator': False, 'error': 'User not found'})

    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error
        return jsonify({'error': 'Database error'}), 500  # Return an error response


# Route to create a user (for testing purposes - remove in production)
@app.route('/create_user', methods=['POST'])
def create_user():
    """
    Creates a new user.  This route is for testing and should be removed in production.
    """
    username = request.form['username']
    password = request.form['password']
    is_moderator = request.form.get('is_moderator', '0') == '1'  # Default to not moderator

    hashed_password = generate_password_hash(password)

    try:
        db = get_db()
        cur = db.cursor()

        # Security: Use parameterized query to prevent SQL injection
        cur.execute("INSERT INTO users (username, password, is_moderator) VALUES (?, ?, ?)",
                    (username, hashed_password, is_moderator))
        db.commit()
        close_db(db)

        return jsonify({'message': 'User created successfully'})

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': 'Database error'}), 500


# Example of command execution prevention (using subprocess securely)
@app.route('/process_data', methods=['POST'])
@login_required
def process_data():
    """
    Example of processing data securely using subprocess.  Avoids shell=True.
    """
    data = request.form['data']

    # Security: Validate and sanitize input data
    if not isinstance(data, str) or len(data) > 100:  # Example validation
        return jsonify({'error': 'Invalid data'}), 400

    # Security: Use subprocess with argument lists, not shell=True
    import subprocess
    try:
        result = subprocess.run(['echo', data], capture_output=True, text=True, check=True)
        output = result.stdout
        return jsonify({'result': output})
    except subprocess.CalledProcessError as e:
        print(f"Command execution error: {e}")
        return jsonify({'error': 'Command execution error'}), 500


# Example of using Content Security Policy (CSP)
@app.after_request
def add_csp_header(response):
    """
    Adds a Content Security Policy header to the response.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
    return response


if __name__ == '__main__':
    app.run(debug=True)  # Disable debug mode in production

