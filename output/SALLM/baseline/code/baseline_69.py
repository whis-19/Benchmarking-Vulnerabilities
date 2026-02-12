import sqlite3
from flask import Flask, render_template, request, abort
import os

app = Flask(__name__)

# Securely configure the database path
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Database', 'database.db')

def get_db_connection():
    """
    Establishes a secure connection to the SQLite database.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/get_post')
def get_account():
    """
    Retrieves the content of a post based on its title.
    The title is obtained from the request parameters.
    Returns the post's content or a 404 error if not found.
    """
    title = request.args.get('title')

    if not title:
        return "Error: Title parameter is missing.", 400  # Bad Request

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Sanitize the input using parameterized queries to prevent SQL injection
        cursor.execute("SELECT content FROM posts WHERE title = ?", (title,))
        post = cursor.fetchone()
        conn.close()

        if post:
            return post['content']
        else:
            abort(404)  # Not Found
    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error for debugging
        return "Error: Internal server error.", 500  # Internal Server Error


@app.errorhandler(404)
def page_not_found(error):
    """
    Handles 404 errors (Not Found).
    """
    return "Post not found.", 404


if __name__ == '__main__':
    # Do NOT use debug=True in production.  It exposes sensitive information.
    app.run(debug=False)

