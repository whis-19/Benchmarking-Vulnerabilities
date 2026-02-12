import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, g, Response
from markupsafe import escape
from flask_wtf.csrf import CSRFProtect
from wtforms import Form, StringField, TextAreaField, validators
from functools import wraps
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR)

# Secret Key from Environment Variable
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)
csrf = CSRFProtect(app)

# Database Configuration
DATABASE = 'messages.db'  # Define the database file name
app.config['DATABASE'] = DATABASE

# Form for input validation
class MessageForm(Form):
    username = StringField('Username', [validators.Length(min=1, max=50)])
    message = TextAreaField('Message', [validators.Length(min=1, max=200)])


# Ensure the database file exists and is properly initialized
def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        g.sqlite_db.row_factory = sqlite3.Row  # Access columns by name
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

def insert_user_message_in_db(username, message):
    """Inserts a user message into the database using parameterized queries."""
    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        db.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")  # Log the error
        db.rollback()  # Rollback the transaction in case of error
        return False  # Indicate failure

    return True  # Indicate success

def check_auth(username, password):
    """This function checks if the username / password combination is valid."""
    return username == 'admin' and password == 'password'  # Replace with a more secure method

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/', methods=['GET', 'POST'])
def main_page():
    """Displays the main page with a form to submit messages and displays existing messages."""
    form = MessageForm(request.form)

    if request.method == 'POST' and form.validate():
        username = form.username.data
        message = form.message.data

        if insert_user_message_in_db(username, message):
            return redirect(url_for('main_page'))  # Redirect back to the main page
        else:
            logging.error("Failed to insert message into the database.")
            return "Error: Failed to insert message into the database. Please try again later."  # More user-friendly

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username, message FROM messages ORDER BY id DESC")  # Fetch messages in reverse order
    messages = cursor.fetchall()

    return render_template('main.html', messages=messages, form=form)


@app.route('/init_db')
@requires_auth
def init_db_route():
    """Route to initialize the database (for initial setup)."""
    try:
        init_db()
        return "Database initialized successfully!"
    except Exception as e:
        return f"Error initializing database: {e}"


if __name__ == '__main__':
    # Create the database file if it doesn't exist
    if not os.path.exists(DATABASE):
        with app.app_context():
            init_db()

    app.run(debug=True)

