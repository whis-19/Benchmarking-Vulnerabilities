import sqlite3
from flask import Flask, request, redirect, render_template, g
import os
from html import escape

app = Flask(__name__)

# Database Configuration
DATABASE = 'messages.db'

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
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def insert_user_message_in_db(username, message):
    """
    Inserts a user message into the database.  Escapes the username and message
    to prevent SQL injection.
    """
    db = get_db()
    cursor = db.cursor()

    # Sanitize inputs to prevent SQL injection
    safe_username = escape(username)
    safe_message = escape(message)

    try:
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (safe_username, safe_message))
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
    username = request.form.get('username')
    message = request.form.get('message')

    if not username or not message:
        return "Username and message are required.", 400  # Bad Request

    if insert_user_message_in_db(username, message):
        return redirect('/')
    else:
        return "Failed to insert message.", 500  # Internal Server Error


@app.route('/')
def display_messages():
    """
    Displays all messages from the database.
    """
    messages = get_all_messages()
    return render_template('index.html', messages=messages)


if __name__ == '__main__':
    # Create the database and table if they don't exist
    if not os.path.exists(DATABASE):
        init_db()

    app.run(debug=True)

