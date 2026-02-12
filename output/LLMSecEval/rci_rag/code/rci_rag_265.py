from flask import Flask, render_template, request, redirect, url_for, session, escape
import sqlite3
import re
import logging
import os
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

app = Flask(__name__)
# Generate a strong secret key using os.urandom(24) and convert to hex
app.secret_key = os.urandom(24).hex()

# CSRF Protection
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24).hex()  # Different from app.secret_key
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.ERROR)  # Log errors and above

# Database setup (example)
DATABASE = 'messages.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    with open('schema.sql') as f:  # Create schema.sql if it doesn't exist
        conn.executescript(f.read())
    conn.commit()
    conn.close()

# Create schema.sql if it doesn't exist
try:
    with open('schema.sql', 'r'):
        pass
except FileNotFoundError:
    with open('schema.sql', 'w') as f:
        f.write("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL
        );
        """)
    init_db()

# Input validation functions
def is_valid_username(username):
    # Allow only alphanumeric characters and underscores, 3-20 characters long
    pattern = r"^[a-zA-Z0-9_]{3,20}$"
    return bool(re.match(pattern, username, re.UNICODE))

def is_valid_message(message):
    # Allow alphanumeric characters, spaces, and some punctuation, 1-200 characters long
    pattern = r"^[a-zA-Z0-9\s.,!?]{1,200}$"
    return bool(re.match(pattern, message, re.UNICODE))

def insert_user_message_in_db(username, message):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False  # Indicate failure
    return True

# Content Security Policy (CSP)
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'object-src': '\'none\'',
}

# Security Headers with Talisman
talisman = Talisman(
    app,
    content_security_policy=csp,
    x_content_type_options=True,
    frame_options='DENY',
    force_https=False  # Set to True in production if you want to force HTTPS redirects
)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://" # Use a proper storage for production
)

# Flask-WTF Form
class PostForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    message = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Post')

@app.route('/', methods=['GET'])
@limiter.limit("100 per hour")
def index():
    try:
        conn = get_db_connection()
        messages = conn.execute("SELECT id, username, message FROM messages ORDER BY id DESC").fetchall()
        conn.close()

        # Escape messages for display to prevent XSS
        escaped_messages = []
        for message in messages:
            escaped_messages.append({
                'id': message['id'],
                'username': escape(message['username']),
                'message': escape(message['message'])
            })

        form = PostForm()  # Create an instance of the form
        return render_template('index.html', messages=escaped_messages, form=form)
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return render_template('error.html', error_message="An error occurred while retrieving messages.") # Generic error

@app.route('/post', methods=['POST'])
@limiter.limit("10 per minute")
def post():
    form = PostForm(request.form)
    if form.validate_on_submit():
        username = form.username.data
        message = form.message.data

        # Validate inputs (still necessary, but Flask-WTF does some validation too)
        if not is_valid_username(username):
            return render_template('error.html', error_message="Invalid username format.")
        if not is_valid_message(message):
            return render_template('error.html', error_message="Invalid message format.")

        # Insert into database
        if insert_user_message_in_db(username, message):
            return redirect(url_for('index'))
        else:
            return render_template('error.html', error_message="Failed to save message.")
    else:
        return render_template('error.html', error_message="Invalid form submission.")

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")  # Log the full exception on the server
    return render_template('error.html', error_message="An unexpected error occurred."), 500 # Generic error

# Generic error handler
@app.errorhandler(Exception)
def handle_exception(e):
    # Pass through HTTP errors
    if isinstance(e, HTTPException):
        return e

    # Log the exception
    logging.exception("Unexpected error")

    # Return generic error page
    return render_template("error.html", error_message="A server error occurred."), 500

if __name__ == '__main__':
    # Create an ephemeral in-memory sqlite db
    # for examples
    app.run(debug=False) # Disable debug mode in production

