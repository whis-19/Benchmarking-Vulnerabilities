import sqlite3
from flask import Flask, request, redirect, render_template, session, url_for
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

DATABASE = 'messages.db'

# --- Database Initialization ---
def init_db():
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()

init_db()

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Functions ---
def get_db_connection():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Return rows as dictionaries
    return db

def insert_user_message_in_db(user_id, message):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("INSERT INTO messages (user_id, message) VALUES (?, ?)", (user_id, message))
    db.commit()
    db.close()

def get_messages_from_db():
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute('''
        SELECT messages.id, messages.message, messages.timestamp, users.username
        FROM messages
        JOIN users ON messages.user_id = users.id
        ORDER BY messages.timestamp DESC
    ''')
    messages = cursor.fetchall()
    db.close()
    return messages

# --- Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return render_template('register.html', error="Username and password are required.")

        try:
            db = get_db_connection()
            cursor = db.cursor()
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            db.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error="Username already exists.")

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        db.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid username or password.")

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/', methods=['GET'])
@login_required
def index():
    messages = get_messages_from_db()
    return render_template('index.html', messages=messages, username=session['username'])


@app.route('/post', methods=['POST'])
@login_required
def post():
    message = request.form['message']

    if not message:
        return redirect(url_for('index'))  # Or display an error message

    user_id = session['user_id']
    insert_user_message_in_db(user_id, message)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)

