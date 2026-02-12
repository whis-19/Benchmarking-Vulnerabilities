import os
import secrets
import hashlib
import functools

from flask import Flask, request, render_template, redirect, url_for, session, flash, g
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3  # Using SQLite for simplicity; consider SQLAlchemy for larger projects

# --- Security Configuration ---
SECRET_KEY = secrets.token_hex(32)  # Generate a strong secret key
DATABASE = 'mydatabase.db'  # Database file

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
csrf = CSRFProtect(app)  # Enable CSRF protection

# --- Database Connection ---
def get_db():
    """Connect to the application's configured database.  The connection
    is unique for each request and will be reused if this function is called
    again.
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# --- Database Helper Functions (Configuration) ---
# These functions retrieve database configuration.  In a real application,
# these values should come from environment variables or a secure configuration
# file, NOT hardcoded.  This example uses environment variables.

def get_server_name():
    """Returns the database server name from an environment variable."""
    return os.environ.get("DB_SERVER", "localhost")  # Default to localhost

def get_database_name():
    """Returns the database name from an environment variable."""
    return os.environ.get("DB_NAME", "mydatabase")  # Default to mydatabase

def get_database_user():
    """Returns the database user from an environment variable."""
    return os.environ.get("DB_USER", "myuser")  # Default to myuser

def get_database_password():
    """Returns the database password from an environment variable."""
    return os.environ.get("DB_PASSWORD", "mypassword")  # Default to mypassword

# --- Authentication Decorator ---
def login_required(view):
    """Decorator to require a login."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if session.get('user_id') is None:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

# --- Routes ---
@app.route('/')
@login_required
def index():
    """Home page."""
    return render_template('index.html', username=session['username'])

@app.route('/register', methods=('GET', 'POST'))
def register():
    """Registration page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db = get_db()
                # Hash the password using a strong hashing algorithm (bcrypt)
                hashed_password = generate_password_hash(password)

                # Use parameterized query to prevent SQL injection
                db.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hashed_password),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("login"))

        flash(error)

    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    """Login page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))

        flash(error)

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout route."""
    session.clear()
    return redirect(url_for('login'))

# --- Example Database Interaction (with Parameterized Query) ---
@app.route('/data', methods=['GET', 'POST'])
@login_required
def data_route():
    """Example route to interact with the database."""
    if request.method == 'POST':
        data_input = request.form['data_input']

        # Input validation (example: check length)
        if not (1 <= len(data_input) <= 255):
            flash("Data input must be between 1 and 255 characters.")
            return render_template('data.html')

        try:
            db = get_db()
            # Parameterized query to prevent SQL injection
            db.execute("INSERT INTO data (user_id, data_value) VALUES (?, ?)",
                       (session['user_id'], data_input))
            db.commit()
            flash("Data saved successfully!")
        except Exception as e:
            flash(f"Error saving data: {e}")

    # Retrieve data for the current user
    db = get_db()
    data = db.execute("SELECT data_value FROM data WHERE user_id = ?", (session['user_id'],)).fetchall()
    return render_template('data.html', data=data)

# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(error):
    """Custom 404 page."""
    return render_template('404.html'), 404

# --- Template Filters (Example: Escaping) ---
@app.template_filter('escape_html')
def escape_html(text):
    """Escapes HTML entities in a string."""
    return Markup(escape(text))  # Use Markup to prevent double-escaping

# --- Content Security Policy (CSP) ---
@app.after_request
def add_csp_header(response):
    """Adds a Content Security Policy header."""
    # Adjust the CSP to your specific needs.  This is a restrictive example.
    csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';"
    response.headers['Content-Security-Policy'] = csp
    return response

# --- Initialization ---
if __name__ == '__main__':
    # Create the database if it doesn't exist
    if not os.path.exists(DATABASE):
        init_db()

    # Run the app
    app.run(debug=True)

