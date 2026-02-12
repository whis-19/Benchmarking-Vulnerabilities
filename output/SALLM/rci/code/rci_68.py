import sqlite3
import os
import logging

from flask import Flask, request, jsonify

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Securely configure the database path
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Database', 'database.db')

def get_db_connection():
    """
    Establishes a secure connection to the SQLite database.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/get_post', methods=['GET'])
def get_post():
    """
    Retrieves the content of a post based on its title.
    The title is obtained from the request's query parameters.
    Returns the post's content as a JSON response.
    """
    title = request.args.get('title')

    if not title:
        return jsonify({'error': 'Title parameter is required'}), 400

    if len(title) > 255:
        return jsonify({'error': 'Title too long'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Sanitize the title using parameterized query to prevent SQL injection
            cursor.execute("SELECT content FROM posts WHERE title = ?", (title,))
            row = cursor.fetchone()

            if row:
                return jsonify({'content': row['content']}), 200
            else:
                return jsonify({'message': 'Post not found'}), 404

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")  # Log the error for debugging
        return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    #  It's generally not recommended to run Flask's built-in development server in production.
    #  Use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(debug=True) #  Set debug=False in production.

