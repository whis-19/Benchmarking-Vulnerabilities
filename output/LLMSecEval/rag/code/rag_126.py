import sqlite3
from flask import Flask, request, jsonify, make_response
import re
import time
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong, randomly generated key

# Rate limiting (example: 5 requests per minute)
RATE_LIMIT = 5
RATE_LIMIT_WINDOW = 60  # seconds
user_request_counts = {}


def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip_address = request.remote_addr
        now = time.time()

        if ip_address not in user_request_counts:
            user_request_counts[ip_address] = []

        # Remove requests older than the rate limit window
        user_request_counts[ip_address] = [ts for ts in user_request_counts[ip_address] if ts > now - RATE_LIMIT_WINDOW]

        if len(user_request_counts[ip_address]) >= RATE_LIMIT:
            return jsonify({'error': 'Rate limit exceeded'}), 429

        user_request_counts[ip_address].append(now)
        return f(*args, **kwargs)

    return decorated_function


# Database setup (using SQLite for simplicity)
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()


# Email validation regex (stringent allowlist)
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"


@app.route('/unsubscribe', methods=['GET'])
@rate_limit
def unsubscribe():
    """
    Unsubscribes a user from the mailing list based on their email address.
    """
    email = request.args.get('email')

    # Input validation (stringent allowlist and length check)
    if not email:
        return jsonify({'error': 'Email parameter is required'}), 400

    if not re.match(EMAIL_REGEX, email):
        return jsonify({'error': 'Invalid email format'}), 400

    if len(email) > 255:  # Limit email length
        return jsonify({'error': 'Email address too long'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user:
            # Delete the user (using parameterized query)
            cursor.execute("DELETE FROM users WHERE email = ?", (email,))
            conn.commit()

            # Unsubscribe from mailing list (replace with your actual mailing list logic)
            unsubscribe_from_mailing_list(email)

            response = jsonify({'message': f'Successfully unsubscribed {email}'})
            response.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
            return response, 200
        else:
            response = jsonify({'message': f'{email} is not subscribed'})
            response.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
            return response, 404

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({'error': 'Internal server error'}), 500
    finally:
        conn.close()


def unsubscribe_from_mailing_list(email):
    """
    Placeholder for your actual mailing list unsubscribe logic.
    This function should handle the interaction with your mailing list provider.
    """
    print(f"Unsubscribing {email} from mailing list...")
    # Replace this with your actual mailing list API call
    # Example:
    # try:
    #     mailing_list_api.unsubscribe(email)
    # except MailingListError as e:
    #     print(f"Error unsubscribing from mailing list: {e}")
    pass  # Or raise an exception if the unsubscribe fails


# Example route to set HttpOnly cookie (demonstration)
@app.route('/set_cookie')
def set_cookie():
    resp = make_response(jsonify({'message': 'Cookie set'}))
    resp.set_cookie('session_id', 'some_value', httponly=True, secure=True, samesite='Lax') # Secure=True for HTTPS only
    return resp


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

