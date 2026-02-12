import sqlite3
from flask import Flask, render_template, request, abort
import os
from urllib.parse import urlparse

app = Flask(__name__)

DATABASE = './Database/database.db'
ALLOWED_DOMAINS = ['example.com', 'localhost']  # Example, refine as needed
MAX_CONNECTIONS = 10  # Limit the number of connections

# Connection pool (very basic example, consider a proper library for production)
connection_pool = []

def get_db_connection():
    """
    Establishes a secure connection to the SQLite database using parameterized queries.
    Manages a connection pool to limit the number of connections.
    """
    if len(connection_pool) < MAX_CONNECTIONS:
        try:
            conn = sqlite3.connect(DATABASE)
            conn.row_factory = sqlite3.Row
            connection_pool.append(conn)
            return conn
        except sqlite3.Error as e:
            print(f"Database connection error: {e}")
            abort(500)  # Internal Server Error
    else:
        print("Maximum database connections reached.")
        abort(503)  # Service Unavailable

def close_db_connection(conn):
    """
    Closes a database connection and removes it from the connection pool.
    """
    if conn:
        try:
            conn.close()
            if conn in connection_pool:
                connection_pool.remove(conn)
        except sqlite3.Error as e:
            print(f"Error closing database connection: {e}")

def is_valid_url(url):
    """
    Validates a URL against an allowlist of domains.
    """
    try:
        result = urlparse(url)
        return result.netloc in ALLOWED_DOMAINS and result.scheme in ['http', 'https']
    except:
        return False

@app.route('/get_post')
def get_account():
    """
    Retrieves a post from the database based on the title provided in the request parameters.
    Uses parameterized queries to prevent SQL injection.
    Returns the post's content.
    """
    title = request.args.get('title')

    if not title:
        return "Title is required", 400  # Bad Request

    conn = get_db_connection()
    post = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT content FROM posts WHERE title = ?", (title,))
        row = cur.fetchone()

        if row:
            post = row['content']
        else:
            return "Post not found", 404  # Not Found

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "Internal Server Error", 500
    finally:
        if conn:
            close_db_connection(conn)

    return post, 200

@app.route('/create_post', methods=['POST'])
def create_post():
    """
    Creates a new post in the database.  Demonstrates parameterized queries.
    """
    title = request.form.get('title')
    content = request.form.get('content')

    if not title or not content:
        return "Title and content are required", 400

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO posts (title, content) VALUES (?, ?)", (title, content))
        conn.commit()
        return "Post created successfully", 201  # Created
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
        return "Internal Server Error", 500
    finally:
        if conn:
            close_db_connection(conn)

# Example of input validation and sanitization (more comprehensive validation is needed)
def sanitize_input(input_string):
    """
    A basic example of input sanitization.  Expand this significantly for real-world use.
    """
    # Remove potentially harmful characters (example)
    sanitized_string = input_string.replace(";", "").replace("--", "")
    return sanitized_string

# Example of URL validation
@app.route('/redirect')
def redirect_to_url():
    url = request.args.get('url')

    if not url:
        return "URL is required", 400

    if is_valid_url(url):
        # In a real application, use a proper redirect function from Flask
        # return redirect(url)  # Be extremely careful with user-provided URLs
        return f"Redirecting to: {url} (Redirect disabled for security)", 200 # For demonstration only
    else:
        return "Invalid URL", 400

if __name__ == '__main__':
    # Create the database and table if they don't exist (for demonstration)
    if not os.path.exists('./Database'):
        os.makedirs('./Database')
    conn = sqlite3.connect(DATABASE)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, content TEXT NOT NULL)")
    except sqlite3.Error as e:
        print(f"Error creating table: {e}")
    finally:
        conn.close()

    app.run(debug=True, host='0.0.0.0', ssl_context='adhoc') # Use HTTPS in production

