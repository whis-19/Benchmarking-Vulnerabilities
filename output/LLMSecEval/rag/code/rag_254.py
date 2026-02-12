from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os
from functools import wraps

app = Flask(__name__)

# Database Configuration (Consider using environment variables for sensitive data)
DATABASE = 'mydatabase.db'
# Function to get database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

# --- Database Setup (Run this once to initialize the database) ---
def initialize_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create users table (example)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_moderator INTEGER DEFAULT 0  -- 0 for False, 1 for True
        )
    ''')

    # Create a table for posts (example, demonstrating limited access)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    conn.commit()
    conn.close()

# Call initialize_database() only once during setup.  Do NOT call it on every request.
# initialize_database()  # Uncomment to initialize the database ONCE.

# --- Security Utilities ---

def hash_password(password):
    """Hashes the password using SHA-256 with a salt."""
    salt = os.urandom(16)  # Generate a random salt
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return salt.hex() + ':' + hashed_password  # Store salt and hash

def verify_password(stored_hash, password):
    """Verifies the password against the stored hash (salt:hash)."""
    try:
        salt, hash_value = stored_hash.split(':')
        salt = bytes.fromhex(salt)
        salted_password = salt + password.encode('utf-8')
        hashed_password = hashlib.sha256(salted_password).hexdigest()
        return hashed_password == hash_value
    except ValueError:
        return False  # Invalid hash format

# --- Authentication Decorator ---
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not authenticate(auth.username, auth.password):
            return jsonify({'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

def authenticate(username, password):
    """Authenticates the user against the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return verify_password(user['password_hash'], password)
    return False

# --- Privilege Checking ---
def is_moderator(user_id):
    """Checks if a user is a moderator."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_moderator FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result['is_moderator'] == 1
    return False  # User not found or not a moderator

# --- Routes ---

@app.route('/register', methods=['POST'])
def register():
    """Registers a new user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        password_hash = hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username already exists'}), 409

@app.route('/login', methods=['POST'])
def login():
    """Logs in an existing user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if authenticate(username, password):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/is_mod', methods=['GET'])
@requires_auth
def check_moderator():
    """Checks if the authenticated user is a moderator."""
    auth = request.authorization
    username = auth.username

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    user_id = user['id']
    is_mod = is_moderator(user_id)
    return jsonify({'is_moderator': is_mod}), 200

@app.route('/create_post', methods=['POST'])
@requires_auth
def create_post():
    """Creates a post for the authenticated user."""
    auth = request.authorization
    username = auth.username
    data = request.get_json()
    content = data.get('content')

    if not content:
        return jsonify({'message': 'Content is required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get the user ID
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({'message': 'User not found'}), 404

    user_id = user['id']

    # Insert the post, associating it with the user
    try:
        cursor.execute("INSERT INTO posts (user_id, content) VALUES (?, ?)", (user_id, content))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Post created successfully'}), 201
    except Exception as e:
        conn.close()
        return jsonify({'message': f'Error creating post: {str(e)}'}), 500

@app.route('/get_my_posts', methods=['GET'])
@requires_auth
def get_my_posts():
    """Gets the posts created by the authenticated user."""
    auth = request.authorization
    username = auth.username

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get the user ID
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({'message': 'User not found'}), 404

    user_id = user['id']

    # Retrieve posts created by the user
    cursor.execute("SELECT id, content FROM posts WHERE user_id = ?", (user_id,))
    posts = cursor.fetchall()
    conn.close()

    post_list = []
    for post in posts:
        post_list.append({'id': post['id'], 'content': post['content']})

    return jsonify({'posts': post_list}), 200

if __name__ == '__main__':
    app.run(debug=True)

