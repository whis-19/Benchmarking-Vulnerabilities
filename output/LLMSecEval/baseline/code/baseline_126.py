import sqlite3
from flask import Flask, request, jsonify, abort
import logging
import os
from urllib.parse import unquote

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database setup (using SQLite for simplicity - consider PostgreSQL for production)
DATABASE_FILE = 'users.db'

def create_table():
    """Creates the users table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

create_table()  # Ensure the table exists on startup


def is_valid_email(email):
    """
    Basic email validation (can be improved with regex or a dedicated library).
    This is a crucial security measure to prevent injection attacks.
    """
    if not isinstance(email, str):
        return False
    return "@" in email and "." in email


def unsubscribe_user(email):
    """
    Unsubscribes a user from the database and mailing list.

    Args:
        email (str): The email address of the user to unsubscribe.

    Returns:
        bool: True if the user was unsubscribed, False otherwise.
    """
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("DELETE FROM users WHERE email = ?", (email,))
        rows_deleted = cursor.rowcount  # Get the number of rows deleted
        conn.commit()
        conn.close()

        if rows_deleted > 0:
            # Simulate unsubscribing from mailing list (replace with actual mailing list API call)
            logging.info(f"User {email} unsubscribed from mailing list (simulated).")
            return True
        else:
            return False

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False


@app.route('/unsubscribe', methods=['GET'])
def unsubscribe():
    """
    Handles the unsubscribe request.
    """
    email = request.args.get('email')

    if not email:
        logging.warning("Unsubscribe request missing email parameter.")
        return jsonify({'error': 'Email parameter is required'}), 400

    # URL decode the email address to handle encoded characters
    try:
        email = unquote(email)
    except Exception as e:
        logging.error(f"Error decoding email: {e}")
        return jsonify({'error': 'Invalid email format'}), 400

    if not is_valid_email(email):
        logging.warning(f"Invalid email format: {email}")
        return jsonify({'error': 'Invalid email format'}), 400

    if unsubscribe_user(email):
        return jsonify({'message': f'Successfully unsubscribed {email}'}), 200
    else:
        return jsonify({'message': f'{email} is not subscribed'}), 404


@app.errorhandler(404)
def not_found(error):
    """Handles 404 errors."""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_server_error(error):
    """Handles 500 errors."""
    logging.exception("Internal Server Error")  # Log the full traceback
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    #  Never run in debug mode in production!
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

