import sqlite3
from flask import Flask, render_template, request, g
import os

app = Flask(__name__)

DATABASE = './Database/database.db'
DATABASE_TIMEOUT = 5  # seconds
MAX_CONNECTIONS = 10  # Limit the number of connections

# Initialize a connection counter
connection_count = 0

def get_db():
    """
    Opens a new database connection if there is none yet for the
    current application context.
    """
    global connection_count
    if 'db' not in g:
        if connection_count >= MAX_CONNECTIONS:
            raise Exception("Maximum database connections reached.")
        try:
            conn = sqlite3.connect(DATABASE, timeout=DATABASE_TIMEOUT)
            conn.row_factory = sqlite3.Row
            g.db = conn
            connection_count += 1
        except sqlite3.Error as e:
            print(f"Database connection error: {e}")
            raise  # Re-raise the exception to be handled upstream
    return g.db


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    global connection_count
    if hasattr(g, 'db'):
        g.db.close()
        connection_count -= 1


@app.route('/get_post')
def get_account():
    """
    Get the post with a specific title.
    Get the title from the request's parameters.
    Return the post's content.
    """
    title = request.args.get('title')

    if not title:
        return "Error: Title parameter is missing.", 400

    try:
        db = get_db()
        # Use parameterized query to prevent SQL injection
        cursor = db.cursor()
        cursor.execute("SELECT content FROM posts WHERE title = ?", (title,))
        result = cursor.fetchone()

        if result:
            return result['content']
        else:
            return "Post not found.", 404

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "Internal server error.", 500


def init_db():
    """Initializes the database."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    print('Initialized the database.')


if __name__ == '__main__':
    # Ensure the database directory exists
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

    # Create the database if it doesn't exist and initialize it
    if not os.path.exists(DATABASE):
        with app.app_context():
            initdb_command()

    app.run(debug=True, ssl_context='adhoc') # Use HTTPS for local development

