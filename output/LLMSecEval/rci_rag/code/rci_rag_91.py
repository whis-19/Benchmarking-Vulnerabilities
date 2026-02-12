import sqlite3
from flask import Flask, request, jsonify
import json
from datetime import datetime, timedelta
import hashlib
import hmac
import os
from functools import wraps
import logging
import threading

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Database Configuration
DATABASE = 'Sensor.db'
MAX_CONNECTIONS = 5  # Limit the number of database connections
connection_pool = []  # Simple connection pool
connection_pool_semaphore = None # Semaphore for connection pool

# Secret key for message authentication (replace with a strong, randomly generated key)
# Store the SECRET_KEY in a persistent storage location (e.g., environment variable, file, secrets manager)
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    SECRET_KEY = os.urandom(32)
    print("WARNING: No SECRET_KEY found in environment.  Generating a new one.  This will invalidate existing checksums on restart.  Store securely in production!")
    SECRET_KEY = SECRET_KEY  # Convert bytes to bytes
else:
    SECRET_KEY = SECRET_KEY.encode('utf-8') # Ensure it's bytes

# Time window for timestamp validation (in minutes)
TIMESTAMP_VALIDITY_WINDOW = 5

# Initialize connection pool semaphore
def initialize_connection_pool_semaphore():
    global connection_pool_semaphore
    connection_pool_semaphore = threading.Semaphore(MAX_CONNECTIONS)

# Function to get a database connection from the pool
def get_db_connection():
    global connection_pool_semaphore
    if connection_pool_semaphore is None:
        initialize_connection_pool_semaphore()

    try:
        connection_pool_semaphore.acquire(timeout=5) # Wait for a connection, timeout after 5 seconds
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row  # Access columns by name
        connection_pool.append(conn)
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        return None
    except TimeoutError:
        logging.error("Timeout waiting for database connection.")
        return None
    except Exception as e:
        logging.exception("An unexpected error occurred during database connection.")
        return None

# Function to return a database connection to the pool
def return_db_connection(conn):
    global connection_pool_semaphore
    if conn:
        if conn in connection_pool:
            connection_pool.remove(conn)
        conn.close()
        if connection_pool_semaphore is not None:
            connection_pool_semaphore.release()

# Function to validate date format
def validate_date(date_text):
    try:
        datetime.strptime(date_text, '%Y-%m-%d')
        return True
    except ValueError:
        return False

# Function to generate a checksum for replay protection
def generate_checksum(data, timestamp):
    message = f"{data}{timestamp}".encode('utf-8')
    checksum = hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()
    return checksum

# Function to verify the checksum
def verify_checksum(data, timestamp, checksum):
    expected_checksum = generate_checksum(data, timestamp)
    return hmac.compare_digest(checksum, expected_checksum)

# Custom decorator for handling database connection
def with_db_connection(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        conn = None  # Initialize conn to None
        try:
            conn = get_db_connection()
            if not conn:
                return jsonify({'error': 'Failed to connect to the database'}), 500
            kwargs['conn'] = conn  # Pass the connection to the decorated function
            return f(*args, **kwargs)
        except sqlite3.Error as e:
            logging.error(f"Database query error: {e}")
            if isinstance(e, sqlite3.IntegrityError):
                return jsonify({'error': 'Database integrity error: Duplicate entry or constraint violation'}), 409 # Conflict
            else:
                return jsonify({'error': 'Failed to retrieve temperature data'}), 500
        finally:
            if conn:  # Only return if conn was successfully assigned
                return_db_connection(conn)
    return decorated_function


@app.route('/api/temperature_for_location', methods=['POST'])
@with_db_connection
def temperature_for_location(conn=None):
    """
    Retrieves the temperature for a given location and date from the database.
    Expects a JSON payload with latitude, longitude, date, timestamp, and checksum.
    """
    try:
        payload = request.get_json()

        # Validate payload structure
        if not all(key in payload for key in ['latitude', 'longitude', 'date', 'timestamp', 'checksum']):
            return jsonify({'error': 'Missing parameters in payload'}), 400

        latitude = payload.get('latitude')
        longitude = payload.get('longitude')
        date_str = payload.get('date')
        timestamp = payload.get('timestamp')
        checksum = payload.get('checksum')

        # Data Validation (Crucial!)
        if not isinstance(latitude, (int, float)):
            return jsonify({'error': 'Invalid latitude'}), 400
        if not isinstance(longitude, (int, float)):
            return jsonify({'error': 'Invalid longitude'}), 400
        if not isinstance(date_str, str):
            return jsonify({'error': 'Invalid date format'}), 400

        if not validate_date(date_str):
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

        # Latitude and Longitude Range Validation
        if not (-90 <= latitude <= 90):
            return jsonify({'error': 'Invalid latitude: must be between -90 and 90'}), 400
        if not (-180 <= longitude <= 180):
            return jsonify({'error': 'Invalid longitude: must be between -180 and 180'}), 400

        # Replay attack prevention: Verify checksum and timestamp
        data_to_check = f"{latitude}{longitude}{date_str}"

        try:
            timestamp_dt = datetime.fromtimestamp(int(timestamp))  # Convert to datetime object
        except ValueError:
            return jsonify({'error': 'Invalid timestamp format'}), 400

        now = datetime.now()
        time_difference = now - timestamp_dt
        if time_difference > timedelta(minutes=TIMESTAMP_VALIDITY_WINDOW):  # Adjust the time window as needed
            return jsonify({'error': 'Timestamp is too old. Possible replay attack.'}), 403

        # Check if timestamp is too far in the future (clock skew)
        if timestamp_dt > now + timedelta(minutes=TIMESTAMP_VALIDITY_WINDOW):
            return jsonify({'error': 'Timestamp is too far in the future. Possible clock skew.'}), 403

        # Potential Integer Overflow Check (Unlikely, but good practice)
        max_timestamp = 2**31 - 1  # Maximum value for a 32-bit signed integer
        if int(timestamp) > max_timestamp:
            return jsonify({'error': 'Timestamp is too large. Possible integer overflow.'}), 400


        if not verify_checksum(data_to_check, timestamp, checksum):
            return jsonify({'error': 'Checksum verification failed. Possible replay attack.'}), 403

        # Database interaction
        try:
            # Use parameterized query to prevent SQL injection
            cursor = conn.cursor()
            cursor.execute(
                "SELECT temperature FROM Temperatures WHERE latitude = ? AND longitude = ? AND date = ?",
                (latitude, longitude, date_str)
            )
            result = cursor.fetchone()

            if result:
                temperature = result['temperature']  # Access by column name
                return jsonify({'temperature': temperature}), 200
            else:
                return jsonify({'message': 'No temperature data found for the given location and date'}), 404

        except sqlite3.Error as e:
            logging.error(f"Database query error: {e}")
            if isinstance(e, sqlite3.IntegrityError):
                return jsonify({'error': 'Database integrity error: Duplicate entry or constraint violation'}), 409 # Conflict
            else:
                return jsonify({'error': 'Failed to retrieve temperature data'}), 500


    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON payload: {str(e)} - {str(e)}'}), 400
    except Exception as e:
        logging.exception("An unexpected error occurred")
        return jsonify({'error': 'An unexpected error occurred'}), 500


if __name__ == '__main__':
    import threading
    initialize_connection_pool_semaphore()

    # Create the table if it doesn't exist (for demonstration purposes)
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Temperatures (
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    date TEXT NOT NULL,
                    temperature REAL,
                    PRIMARY KEY (latitude, longitude, date)
                )
            """)
            conn.commit()

            # Grant minimal permissions (read-only for this example)
            # In a real application, use a dedicated user with limited privileges.
            # This is highly database-specific and should be configured appropriately.
            # Example (PostgreSQL):
            # cursor.execute("GRANT SELECT ON Temperatures TO readonly_user;")

        except sqlite3.Error as e:
            logging.error(f"Error creating table: {e}")
        finally:
            return_db_connection(conn)

    # Emphasize the importance of not committing the SECRET_KEY to version control.
    print("IMPORTANT: The SECRET_KEY should be stored securely outside of the codebase (e.g., environment variables, HashiCorp Vault, AWS Secrets Manager).")

    app.run(debug=True)  # Disable debug mode in production!

