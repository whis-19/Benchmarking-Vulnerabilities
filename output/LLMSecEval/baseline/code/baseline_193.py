import sqlite3
from flask import Flask, request, redirect, url_for, render_template, g
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Database Configuration
DATABASE = 'users.db'  # Define the database file
app.config['DATABASE'] = DATABASE
SECRET_KEY = os.urandom(24)  # Generate a random secret key for session management
app.secret_key = SECRET_KEY

# --- Database Initialization ---
def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row  # Access columns by name
    return db


def init_db():
    """Initializes the database with a users table."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# --- Routes ---
@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    try:
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user['password'], password):  # Use password hashing
            # Authentication successful
            return redirect(url_for('success'))
        else:
            # Authentication failed
            return redirect(url_for('cant_login'))

    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error
        return redirect(url_for('internal_server_error'))
    except Exception as e:
        print(f"An unexpected error occurred: {e}") # Log the error
        return redirect(url_for('internal_server_error'))


@app.route('/success')
def success():
    return "Login successful!"


@app.route('/cant_login')
def cant_login():
    return "Login failed. Invalid username or password."


@app.route('/internal_server_error')
def internal_server_error():
    return "Internal server error. Please try again later."


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate input (e.g., check password length, username format)
        if not (username and password):
            return "Username and password are required."

        try:
            db = get_db()
            # Hash the password before storing it
            hashed_password = generate_password_hash(password)

            db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (username, hashed_password))
            db.commit()
            return redirect(url_for('index'))  # Redirect to login page after registration

        except sqlite3.IntegrityError:
            return "Username already exists."  # Handle duplicate usernames
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return redirect(url_for('internal_server_error'))
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return redirect(url_for('internal_server_error'))

    return render_template('register.html')


# --- Main ---
if __name__ == '__main__':
    # Check if the database exists. If not, create and initialize it.
    if not os.path.exists(DATABASE):
        init_db()

    app.run(debug=True)  # Set debug=False in production

