import sqlite3
from flask import Flask, render_template, request, redirect, url_for, g
import os

app = Flask(__name__)

# Database Configuration
DATABASE = 'messages.db'

# Ensure the database file exists
if not os.path.exists(DATABASE):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
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


def insert_user_message_in_db(username, message):
    """Inserts a user message into the database, escaping parameters to prevent SQL injection."""
    db = get_db()
    cursor = db.cursor()
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
    """Handles the main page, displaying messages and processing new posts."""
    if request.method == 'POST':
        return post()  # Delegate to the post function

    # Fetch messages from the database for display
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, message, timestamp FROM messages ORDER BY timestamp DESC")
    messages = cursor.fetchall()

    return render_template('main.html', messages=messages)


def post():
    """Handles the submission of a new message."""
    username = request.form.get('username')
    message = request.form.get('message')

    # Input Validation:  Important security measure
    if not username or not message:
        return "Error: Username and message are required.", 400  # Return an error response

    if len(username) > 50:
        return "Error: Username too long.", 400

    if len(message) > 500:
        return "Error: Message too long.", 400

    # Sanitize input (basic example, consider using a more robust library)
    username = username.strip()
    message = message.strip()

    # Insert the message into the database
    if insert_user_message_in_db(username, message):
        return redirect(url_for('main_page'))  # Redirect on success
    else:
        return "Error: Failed to save message.", 500  # Return an error response


@app.route('/delete/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    """Deletes a message from the database.  Requires authentication/authorization in a real application."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        db.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        db.rollback()
        return "Error deleting message.", 500
    return redirect(url_for('main_page'))


@app.route('/edit/<int:message_id>', methods=['GET', 'POST'])
def edit_message(message_id):
    """Allows editing of a message.  Requires authentication/authorization in a real application."""
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        new_message = request.form.get('message')

        # Input validation for the new message
        if not new_message:
            return "Error: Message cannot be empty.", 400
        if len(new_message) > 500:
            return "Error: Message too long.", 400

        try:
            cursor.execute("UPDATE messages SET message = ? WHERE id = ?", (new_message, message_id))
            db.commit()
            return redirect(url_for('main_page'))
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            db.rollback()
            return "Error updating message.", 500

    # GET request: display the edit form
    cursor.execute("SELECT id, username, message FROM messages WHERE id = ?", (message_id,))
    message = cursor.fetchone()

    if message:
        return render_template('edit.html', message=message)
    else:
        return "Message not found.", 404


if __name__ == '__main__':
    app.run(debug=True)

