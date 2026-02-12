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

def get_db_connection():
    """Connects to the database."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Return rows as dictionaries
    return db

def insert_user_message_in_db(username, message):
    """Inserts a user message into the database, using parameterized queries."""
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        db.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error for debugging
        db.rollback()  # Rollback in case of error
        return False  # Indicate failure
    finally:
        db.close()
    return True  # Indicate success

def get_messages_from_db():
    """Retrieves all messages from the database, ordered by timestamp."""
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, message, timestamp FROM messages ORDER BY timestamp DESC")
        messages = cursor.fetchall()
        return messages
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []  # Return an empty list in case of error
    finally:
        db.close()

@app.route('/', methods=['GET', 'POST'])
def main_page():
    """Handles the main page, displaying messages and processing new posts."""
    if request.method == 'POST':
        return post()  # Delegate to the post() function

    messages = get_messages_from_db()
    return render_template('index.html', messages=messages, username=session.get('username'))

@app.route('/post', methods=['POST'])
def post():
    """Handles the submission of a new message."""
    if 'username' not in session:
        return redirect('/login')  # Redirect to login if not logged in

    username = session['username']  # Get username from session
    message = request.form.get('message')

    if not message:
        return "Message cannot be empty.", 400  # Return an error if message is empty

    if insert_user_message_in_db(username, message):
        return redirect('/')  # Redirect to the main page after successful post
    else:
        return "Failed to save message.", 500  # Return an error if saving fails

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            session['username'] = username  # Store username in session
            return redirect('/')
        else:
            return "Username cannot be empty.", 400
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Handles user logout."""
    session.pop('username', None)  # Remove username from session
    return redirect('/')

# Example template (index.html)
# Create a templates directory and put this file inside
# <!DOCTYPE html>
# <html>
# <head>
#     <title>Message Board</title>
# </head>
# <body>
#     <h1>Message Board</h1>
#     {% if username %}
#         <p>Logged in as: {{ username }} <a href="/logout">Logout</a></p>
#         <form action="/post" method="post">
#             <textarea name="message" rows="4" cols="50"></textarea><br>
#             <button type="submit">Post Message</button>
#         </form>
#     {% else %}
#         <p><a href="/login">Login</a> to post messages.</p>
#     {% endif %}
#
#     <h2>Messages:</h2>
#     <ul>
#         {% for message in messages %}
#             <li><strong>{{ message.username }}</strong> ({{ message.timestamp }}): {{ message.message }}</li>
#         {% endfor %}
#     </ul>
# </body>
# </html>

# Example template (login.html)
# Create a templates directory and put this file inside
# <!DOCTYPE html>
# <html>
# <head>
#     <title>Login</title>
# </head>
# <body>
#     <h1>Login</h1>
#     <form action="/login" method="post">
#         <label for="username">Username:</label>
#         <input type="text" id="username" name="username"><br><br>
#         <button type="submit">Login</button>
#     </form>
# </body>
# </html>

if __name__ == '__main__':
    app.run(debug=True)

