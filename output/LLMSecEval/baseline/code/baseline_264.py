import sqlite3
from flask import Flask, request, redirect, render_template, session, escape

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong, randomly generated key

DATABASE = 'messages.db'  # Define the database file

# Initialize the database (create table if it doesn't exist)
def init_db():
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()

init_db()  # Call the initialization function when the app starts

def get_db():
    """Connects to the database."""
    db = getattr(app, '_database', None)
    if db is None:
        db = app._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(app, '_database', None)
    if db is not None:
        db.close()


def insert_user_message_in_db(username, message):
    """Inserts a user message into the database, escaping user input."""
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


def get_all_messages():
    """Retrieves all messages from the database, ordered by timestamp."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT username, message, timestamp FROM messages ORDER BY timestamp DESC")
        messages = cursor.fetchall()
        return messages
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []  # Return an empty list in case of error


@app.route('/', methods=['GET', 'POST'])
def main_page():
    """Handles the main page, displaying messages and handling new posts."""
    if request.method == 'POST':
        return post()  # Delegate to the post() function

    messages = get_all_messages()
    return render_template('main.html', messages=messages, username=session.get('username'))


@app.route('/post', methods=['POST'])
def post():
    """Handles the submission of a new message."""
    if 'username' not in session:
        return redirect('/login')  # Redirect to login if not logged in

    username = session['username']
    message = request.form.get('message')

    if not message:
        return "Message cannot be empty."  # Handle empty messages

    # Input validation and sanitization (important for security)
    if len(message) > 500:  # Limit message length
        return "Message too long (max 500 characters)."

    # Insert the message into the database
    if insert_user_message_in_db(username, message):
        return redirect('/')  # Redirect to the main page after successful post
    else:
        return "Error posting message."  # Handle database insertion failure


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            session['username'] = username  # Store username in session
            return redirect('/')
        else:
            return "Username cannot be empty."
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Handles user logout."""
    session.pop('username', None)  # Remove username from session
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)

