import sqlite3
import hashlib
import os

from flask import Flask, request, g, make_response, session
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong secret key

DATABASE = './Database/database.db'

def get_db():
    """
    Gets the database connection.
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """
    Closes the database connection.
    """
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """
    Initializes the database with stricter permissions.
    """
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Example schema.sql (adjust to your needs):
# CREATE TABLE IF NOT EXISTS posts (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     title TEXT NOT NULL,
#     content TEXT NOT NULL,
#     user_id INTEGER NOT NULL,
#     FOREIGN KEY (user_id) REFERENCES users (id)
# );
#
# CREATE TABLE IF NOT EXISTS users (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     username TEXT NOT NULL UNIQUE,
#     password_hash TEXT NOT NULL
# );
#
# -- Grant minimal permissions
# -- Example for PostgreSQL (adapt for SQLite if needed, but SQLite's security is limited)
# -- CREATE USER readonly WITH PASSWORD 'readonly_password';
# -- GRANT SELECT ON posts TO readonly;
# -- CREATE USER readwrite WITH PASSWORD 'readwrite_password';
# -- GRANT SELECT, INSERT, UPDATE, DELETE ON posts TO readwrite;
# -- REVOKE ALL PRIVILEGES ON posts FROM public; -- Remove default public access

def is_safe_url(target):
    """
    Checks if a URL is safe for redirection.  Prevents open redirects.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


@app.route('/get_post')
def get_post():
    """
    Get the post with a specific title.
    Get the title from the request's parameters.
    Return the post's content.
    """
    title = request.args.get('title')

    # Input validation:  Strict allowlist for title (alphanumeric and spaces only)
    if not title or not all(c.isalnum() or c.isspace() for c in title):
        return "Invalid title format.  Only alphanumeric characters and spaces are allowed.", 400

    try:
        db = get_db()
        # Use parameterized query to prevent SQL injection
        cur = db.execute("SELECT content FROM posts WHERE title = ?", (title,))
        post = cur.fetchone()
        cur.close()

        if post:
            response = make_response(post['content'])
            response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
            return response
        else:
            return "Post not found", 404

    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error
        return "Internal server error", 500


@app.route('/create_user', methods=['POST'])
def create_user():
    """
    Creates a new user account.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    # Input validation:  Strict allowlist for username (alphanumeric only)
    if not username or not username.isalnum():
        return "Invalid username format. Only alphanumeric characters are allowed.", 400

    if not password:
        return "Password cannot be empty.", 400

    try:
        db = get_db()
        # Hash the password before storing it
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        # Use parameterized query to prevent SQL injection
        try:
            cur = db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            cur.close()
            return "User created successfully", 201
        except sqlite3.IntegrityError:
            return "Username already exists", 409

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "Internal server error", 500


@app.route('/login', methods=['POST'])
def login():
    """
    Logs in an existing user.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    # Input validation:  Strict allowlist for username (alphanumeric only)
    if not username or not username.isalnum():
        return "Invalid username format. Only alphanumeric characters are allowed.", 400

    if not password:
        return "Password cannot be empty.", 400

    try:
        db = get_db()
        cur = db.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        cur.close()

        if user:
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            if hashed_password == user['password_hash']:
                session['user_id'] = user['id']  # Store user ID in session
                # Set HttpOnly flag for session cookie
                resp = make_response("Login successful")
                resp.set_cookie('session', session['user_id'], httponly=True)

                next_url = request.args.get('next')
                if next_url and is_safe_url(next_url):
                    return redirect(next_url)
                else:
                    return "Login successful", 200
            else:
                return "Invalid credentials", 401
        else:
            return "Invalid credentials", 401

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "Internal server error", 500

from flask import redirect

@app.route('/logout')
def logout():
    """
    Logs out the current user.
    """
    session.pop('user_id', None)
    return "Logged out successfully", 200

if __name__ == '__main__':
    # Initialize the database (if it doesn't exist)
    if not os.path.exists(DATABASE):
        init_db()

    app.run(debug=True)

