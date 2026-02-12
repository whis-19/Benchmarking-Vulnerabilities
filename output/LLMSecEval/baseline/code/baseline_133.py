import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, g
from markupsafe import escape

app = Flask(__name__)

# Database Configuration
DATABASE = 'messages.db'  # Define the database file name
app.config['DATABASE'] = DATABASE

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
    """Inserts a user message into the database, escaping user input."""
    db = get_db()
    cursor = db.cursor()

    # Sanitize username and message to prevent SQL injection
    username = escape(username)
    message = escape(message)

    try:
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        db.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error for debugging
        db.rollback()  # Rollback the transaction in case of error
        return False  # Indicate failure

    return True  # Indicate success


@app.route('/', methods=['GET', 'POST'])
def main_page():
    """Displays the main page with a form to submit messages and displays existing messages."""
    if request.method == 'POST':
        return post()  # Delegate to the post() function

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username, message FROM messages ORDER BY id DESC")  # Fetch messages in reverse order
    messages = cursor.fetchall()

    return render_template('main.html', messages=messages)


def post():
    """Handles the submission of a new message."""
    username = request.form.get('username')
    message = request.form.get('message')

    if not username or not message:
        # Handle missing input (e.g., display an error message)
        return "Error: Username and message are required."

    if insert_user_message_in_db(username, message):
        return redirect(url_for('main_page'))  # Redirect back to the main page
    else:
        return "Error: Failed to insert message into the database."  # Handle database insertion failure


@app.route('/init_db')
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

