import base64
import os
import hashlib
import secrets
import sqlite3  # Consider using a more robust database like PostgreSQL with an ORM
from flask import Flask, request, session, redirect, url_for, abort
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Replace with a strong, randomly generated key

DATABASE = 'image_database.db'  # Consider using environment variables for configuration

# --- Database Initialization and Helper Functions ---

def get_db():
    """Connects to the database.  Consider using a connection pool."""
    db = getattr(app, '_database', None)
    if db is None:
        db = app._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(app, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database schema.  Run this once."""
    with app.app_context():
        db = get_db()
        with open('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# --- Authentication ---

def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC."""
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return salt, dk.hex()

def verify_password(stored_salt, stored_hash, password):
    """Verifies the password against the stored hash."""
    _, new_hash = hash_password(password, stored_salt)
    return secrets.compare_digest(stored_hash, new_hash)

def login_required(f):
    """Decorator to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return "Username and password are required", 400

        db = get_db()
        cur = db.cursor()

        # Check if username already exists
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone() is not None:
            return "Username already exists", 400

        # Hash the password
        salt, hashed_password = hash_password(password)

        # Insert the user into the database
        try:
            cur.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                        (username, hashed_password, salt))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            db.rollback()
            return f"Database error: {e}", 500

    return '''
        <form method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Register</button>
        </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cur = db.cursor()

        cur.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user is None:
            return "Invalid username or password", 401

        user_id, stored_hash, stored_salt = user

        if verify_password(stored_salt, stored_hash, password):
            session['user_id'] = user_id
            return redirect(url_for('upload_image'))  # Redirect to upload page
        else:
            return "Invalid username or password", 401

    return '''
        <form method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    '''

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_image():
    if request.method == 'POST':
        if 'image' not in request.files:
            return "No image part", 400

        image_file = request.files['image']

        if image_file.filename == '':
            return "No selected image", 400

        filename = image_file.filename
        ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowlist of extensions
        if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
            return "Invalid file extension. Allowed extensions are: png, jpg, jpeg, gif", 400

        try:
            image_data = image_file.read()
            image_base64 = base64.b64encode(image_data).decode('utf-8')

            db = get_db()
            cur = db.cursor()

            # Get the user ID from the session
            user_id = session['user_id']

            # Insert image data into the database, associating it with the user
            try:
                cur.execute(
                    "INSERT INTO images (filename, image_data, user_id) VALUES (?, ?, ?)",
                    (filename, image_base64, user_id)
                )
                db.commit()
                return "Image uploaded successfully!"
            except sqlite3.Error as e:
                db.rollback()
                return f"Database error: {e}", 500

        except Exception as e:
            return f"Error processing image: {e}", 500

    return '''
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="image">
            <button type="submit">Upload</button>
        </form>
    '''

@app.route('/images')
@login_required
def list_images():
    """Lists images uploaded by the logged-in user."""
    user_id = session['user_id']
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT filename FROM images WHERE user_id = ?", (user_id,))
    images = cur.fetchall()

    image_list = "<ul>"
    for image in images:
        image_list += f"<li>{image['filename']}</li>"
    image_list += "</ul>"

    return f"<h1>Your Images</h1>{image_list}"

@app.route('/image/<filename>')
@login_required
def get_image(filename):
    """Retrieves and displays an image uploaded by the logged-in user."""
    user_id = session['user_id']
    db = get_db()
    cur = db.cursor()

    # Prevent path traversal
    if ".." in filename:
        abort(400)  # Or return a more informative error

    cur.execute("SELECT image_data FROM images WHERE filename = ? AND user_id = ?", (filename, user_id))
    image = cur.fetchone()

    if image:
        image_data = base64.b64decode(image['image_data'])
        return f'<img src="data:image/png;base64,{image["image_data"]}" alt="{filename}">' # Assuming PNG for simplicity.  Determine content type dynamically if possible.
    else:
        return "Image not found or you do not have permission to view it.", 404


if __name__ == '__main__':
    # Create the database if it doesn't exist.  Consider using migrations for schema changes.
    if not os.path.exists(DATABASE):
        init_db()

    app.run(debug=True)

