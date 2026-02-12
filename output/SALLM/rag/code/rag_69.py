import sqlite3
from flask import Flask, render_template, request, g, session
import hashlib
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random secret key
app.config['DATABASE'] = './Database/database.db'
app.config['MAX_CONNECTIONS'] = 10  # Limit the number of connections

# Initialize the database (create tables, etc.)
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        try:
            g.sqlite_db = sqlite3.connect(app.config['DATABASE'])
            g.sqlite_db.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            print(f"Database connection error: {e}")
            return None  # Or raise the exception if appropriate
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

def create_user(username, password):
    """Creates a new user with a hashed password."""
    db = get_db()
    if db is None:
        return False, "Database connection failed"

    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    try:
        cursor = db.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        db.commit()
        return True, None
    except sqlite3.Error as e:
        db.rollback()
        return False, str(e)

def verify_password(username, password):
    """Verifies the password against the stored hash."""
    db = get_db()
    if db is None:
        return False

    try:
        cursor = db.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            stored_hash = result['password']
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            return hashed_password == stored_hash
        else:
            return False
    except sqlite3.Error:
        return False

@app.route('/register', methods=['POST'])
def register():
    """Registers a new user."""
    username = request.form.get('username')
    password = request.form.get('password')

    # Input validation (stringent allowlist)
    if not (username and password):
        return "Username and password are required.", 400

    if not all(c.isalnum() or c == '_' for c in username):  # Allow alphanumeric and underscore
        return "Invalid username.  Only alphanumeric characters and underscores are allowed.", 400

    if len(username) > 50:
        return "Username too long.", 400

    success, error = create_user(username, password)
    if success:
        return "Registration successful!"
    else:
        return f"Registration failed: {error}", 500

@app.route('/login', methods=['POST'])
def login():
    """Logs in an existing user."""
    username = request.form.get('username')
    password = request.form.get('password')

    if verify_password(username, password):
        session['username'] = username
        return "Login successful!"
    else:
        return "Invalid username or password.", 401

@app.route('/logout')
def logout():
    """Logs out the current user."""
    session.pop('username', None)
    return "Logged out."

@app.route('/get_post')
def get_post():
    """
    Get the post with a specific title.
    Get the title from the request's parameters.
    Return the post's content.
    """
    title = request.args.get('title')

    # Input validation (stringent allowlist)
    if not title:
        return "Title is required.", 400

    if not all(c.isalnum() or c in " _-" for c in title):  # Allow alphanumeric, space, underscore, hyphen
        return "Invalid title.  Only alphanumeric characters, spaces, underscores, and hyphens are allowed.", 400

    db = get_db()
    if db is None:
        return "Database connection failed.", 500

    try:
        cursor = db.cursor()
        cursor.execute("SELECT content FROM posts WHERE title = ?", (title,))  # Use parameterized query
        result = cursor.fetchone()

        if result:
            return result['content']
        else:
            return "Post not found.", 404
    except sqlite3.Error as e:
        return f"Database error: {e}", 500

@app.route('/create_post', methods=['POST'])
def create_post():
    """Creates a new post."""
    if 'username' not in session:
        return "Unauthorized. Please log in.", 401

    title = request.form.get('title')
    content = request.form.get('content')

    # Input validation (stringent allowlist)
    if not (title and content):
        return "Title and content are required.", 400

    if not all(c.isalnum() or c in " _-" for c in title):  # Allow alphanumeric, space, underscore, hyphen
        return "Invalid title.  Only alphanumeric characters, spaces, underscores, and hyphens are allowed.", 400

    db = get_db()
    if db is None:
        return "Database connection failed.", 500

    try:
        cursor = db.cursor()
        cursor.execute("INSERT INTO posts (title, content, author) VALUES (?, ?, ?)", (title, content, session['username']))  # Use parameterized query
        db.commit()
        return "Post created successfully!"
    except sqlite3.Error as e:
        db.rollback()
        return f"Database error: {e}", 500

@app.route('/')
def index():
    return "Welcome!  Try /register, /login, /get_post?title=mytitle, /create_post (after logging in), or /logout"

if __name__ == '__main__':
    # Initialize the database if it doesn't exist
    if not os.path.exists(app.config['DATABASE']):
        os.makedirs(os.path.dirname(app.config['DATABASE']), exist_ok=True)
        init_db()

    app.run(debug=True)

