import sqlite3
from flask import Flask, request, redirect, render_template, g, abort
import os
import re
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import Form, StringField, TextAreaField, validators

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong secret key
csrf = CSRFProtect(app)

# Database Configuration
DATABASE = 'messages.db'
DATABASE_PATH = os.path.join(app.root_path, DATABASE)  # Store DB in app directory

# Input Validation Constants
MAX_USERNAME_LENGTH = 50
MAX_MESSAGE_LENGTH = 500
ALLOWED_USERNAME_CHARS = r"^[a-zA-Z0-9_]+$"  # Alphanumeric and underscore

# Form for input validation
class MessageForm(Form):
    username = StringField('Username', [validators.Length(min=1, max=MAX_USERNAME_LENGTH)])
    message = TextAreaField('Message', [validators.Length(min=1, max=MAX_MESSAGE_LENGTH)])

# Ensure the database file exists and create the table if it doesn't
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def insert_user_message_in_db(username, message):
    """
    Inserts a user message into the database using parameterized queries.
    """
    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        db.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        db.rollback()  # Rollback in case of error
        return False  # Indicate failure
    finally:
        cursor.close()
    return True # Indicate success


def get_all_messages():
    """
    Retrieves all messages from the database.
    """
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT username, message FROM messages ORDER BY id DESC")
        messages = cursor.fetchall()
        return messages
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        cursor.close()


@app.route('/post', methods=['POST'])
def post_message():
    """
    Handles the /post route.  Gets username and message from the request,
    inserts the message into the database, and redirects to the / route.
    """
    form = MessageForm(request.form)
    if form.validate():
        username = form.username.data  # No escaping here
        message = form.message.data    # No escaping here

        # Additional input validation using regex
        if not re.match(ALLOWED_USERNAME_CHARS, username):
            return "Invalid username. Only alphanumeric characters and underscores are allowed.", 400

        if insert_user_message_in_db(username, message):
            return redirect('/')
        else:
            return "Failed to insert message.", 500  # Internal Server Error
    else:
        return render_template('index.html', messages=get_all_messages(), form=form, errors=form.errors), 400


@app.route('/')
def display_messages():
    """
    Displays all messages from the database.
    """
    messages = get_all_messages()
    form = MessageForm()
    return render_template('index.html', messages=messages, form=form)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400


if __name__ == '__main__':
    # Create the database and table if they don't exist
    if not os.path.exists(DATABASE_PATH):
        init_db()

    app.run(debug=False) # Disable debug mode in production

