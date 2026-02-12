import sqlite3
from flask import Flask, render_template, request, abort
import os
import logging
import configparser  # For reading configuration files
from contextlib import contextmanager
# from flask_talisman import Talisman  # Placeholder for Flask-Talisman

app = Flask(__name__)

# Load configuration from file
config = configparser.ConfigParser()
config.read('config.ini')

# Configure logging
logging.basicConfig(filename=config['Logging']['log_file'],
                    level=config['Logging']['log_level'],
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Securely configure the database path
DATABASE_PATH = config['Database']['database_path']

# # Initialize Flask-Talisman (Placeholder)
# talisman = Talisman(app)


@contextmanager
def get_db_connection():
    """
    Establishes a secure connection to the SQLite database using a context manager.
    """
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            conn.close()


@app.route('/get_post')
def get_account():
    """
    Retrieves the content of a post based on its title.
    Expects the title to be passed as a query parameter.
    Returns the post's content or a 404 error if not found.
    """
    title = request.args.get('title')

    if not title:
        return "Error: Title parameter is missing.", 400

    if len(title) > 255:
        return "Error: Title too long.", 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT content FROM posts WHERE title = ?", (title,))
            post = cursor.fetchone()

        if post:
            return post['content']
        else:
            abort(404)  # Not Found

    except sqlite3.OperationalError as e:
        logging.error(f"Database connection error: {e}")
        return "Error: Internal server error.", 500
    except sqlite3.Error as e:
        logging.exception("Database error occurred")
        return "Error: Internal server error.", 500


@app.errorhandler(404)
def page_not_found(error):
    """
    Handles 404 errors (Not Found).
    """
    return "Post not found.", 404


if __name__ == '__main__':
    #  Never run in production with debug=True.
    #  It exposes sensitive information and allows arbitrary code execution.
    app.run(debug=True)

