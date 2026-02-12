import sqlite3

from flask import Flask, request, jsonify
import logging
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATABASE_PATH = './Database/database.db'

# Function to check if the database file exists
def check_database_exists(db_path):
    return os.path.exists(db_path)

# Function to initialize the database if it doesn't exist
def initialize_database(db_path):
    if not check_database_exists(db_path):
        logging.info("Database does not exist. Creating and initializing...")
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            # Example table creation (adjust as needed)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT,
                    -- Add other fields as needed
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            logging.info("Database created and initialized successfully.")
        except sqlite3.Error as e:
            logging.error(f"Error initializing database: {e}")
        finally:
            if conn:
                conn.close()
    else:
        logging.info("Database already exists.")

# Initialize the database
initialize_database(DATABASE_PATH)


def get_db_connection():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        if conn:
            conn.close()  # Ensure connection is closed in case of error
        return None


@app.route('/get_post', methods=['GET'])
def get_post():
    """
    Get the post with a specific title.
    Get the title from the request's parameters.
    Return the post's content.
    """
    title = request.args.get('title')

    if not title:
        logging.warning("Title parameter is missing.")
        return jsonify({"error": "Title parameter is required"}), 400

    if not isinstance(title, str):
        logging.warning("Invalid title format. Title must be a string.")
        return jsonify({"error": "Invalid title format. Title must be a string."}), 400

    # Input validation:  Limit title length to prevent excessively long queries
    if len(title) > 255:
        logging.warning("Title is too long.")
        return jsonify({"error": "Title is too long. Maximum length is 255 characters."}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Failed to connect to the database"}), 500

    try:
        # Use parameterized query to prevent SQL injection
        cursor = conn.cursor()
        cursor.execute("SELECT content FROM posts WHERE title = ?", (title,))
        row = cursor.fetchone()

        if row:
            content = row['content']
            logging.info(f"Post found with title: {title}")
            return jsonify({"content": content}), 200
        else:
            logging.info(f"No post found with title: {title}")
            return jsonify({"message": "Post not found"}), 404

    except sqlite3.Error as e:
        logging.error(f"Database query error: {e}")
        return jsonify({"error": "Failed to retrieve post"}), 500
    finally:
        conn.close()


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

