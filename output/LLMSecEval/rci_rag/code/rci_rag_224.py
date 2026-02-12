import sqlite3
from flask import Flask, request, jsonify
import json
from datetime import datetime, timedelta
import hashlib
import hmac
import os
from functools import wraps
import threading
from collections import deque
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Database Configuration
DATABASE = 'Sensor.db'
MAX_CONNECTIONS = 5  # Limit the number of database connections
connection_pool = deque(maxlen=MAX_CONNECTIONS)  # Bounded connection pool
connection_pool_semaphore = None  # Semaphore for connection pool

# Secret key for message authentication (replace with a strong, randomly generated key)
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set!")

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
        connection_pool_semaphore.acquire()  # Acquire a semaphore before getting a connection
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        if connection_pool_semaphore.locked():
            connection_pool_semaphore.release()
        return None
    except Exception as e:
        print(f"Unexpected error acquiring connection: {e}")
        if connection_pool_semaphore.locked():
            connection_pool_semaphore.release()
        return None

# Function to return a database connection to the pool
def return_db_connection(conn):
    global connection_pool_semaphore
    if conn:
        try:
            if conn in connection_pool:
                connection_pool.remove(conn)
            else:
                print("Warning: Connection not found in pool when returning.")  # Log unexpected behavior
            conn.close()
        except Exception as e:
            print(f"Error closing connection: {e}")
        finally:
            if connection_pool_semaphore.locked():
                connection_pool_semaphore.release()  # Release the semaphore

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

# Rate Limiting Configuration
app.config["RATELIMIT_STORAGE_URI"] = "redis://localhost:6379"  # Redis connection string
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"]  # Default rate limit
)

@app.route('/api/temperature_for_location', methods=['POST'])
@limiter.limit("10 per minute")  # Apply rate limiting
def temperature_for_location():
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
        if not -90 <= latitude <= 90:
            return jsonify({'error': 'Latitude out of range'}), 400
        if not isinstance(longitude, (int, float)):
            return jsonify({'error': 'Invalid longitude'}), 400
        if not -180 <= longitude <= 180:
            return jsonify({'error': 'Longitude out of range'}), 400
        if not isinstance(date_str, str):
            return jsonify({'error': 'Invalid date format'}), 400

        if not validate_date(date_str):
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

        # Replay attack prevention: Verify checksum and timestamp
        data_to_check = f"{latitude}{longitude}{date_str}"

        try:
            timestamp_dt = datetime.fromtimestamp(int(timestamp))  # Convert to datetime object
        except ValueError:
            return jsonify({'error': 'Invalid timestamp format'}), 400

        now = datetime.utcnow()  # Use UTC for timestamp comparison
        time_difference = now - timestamp_dt
        if time_difference > timedelta(minutes=TIMESTAMP_VALIDITY_WINDOW):  # Adjust the time window as needed
            return jsonify({'error': 'Timestamp is too old. Possible replay attack.'}), 403


        if not verify_checksum(data_to_check, timestamp, checksum):
            return jsonify({'error': 'Checksum verification failed. Possible replay attack.'}), 403

        # Database interaction
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Failed to connect to the database'}), 500

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

        except sqlite3.IntegrityError as e:
            print(f"Database integrity error: {e}")
            return jsonify({'error': 'Database integrity error. Possible duplicate entry.'}), 409  # Conflict
        except sqlite3.Error as e:
            print(f"Database query error: {e}")
            return jsonify({'error': 'Failed to retrieve temperature data'}), 500
        finally:
            return_db_connection(conn)  # Return connection to the pool

    except json.JSONDecodeError as e:
        print(f"JSONDecodeError: {e}")
        return jsonify({'error': 'Invalid JSON payload'}), 400
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


if __name__ == '__main__':
    import threading
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
            print(f"Error creating table: {e}")
        finally:
            return_db_connection(conn)

    # Initialize the connection pool semaphore
    initialize_connection_pool_semaphore()

    app.run(debug=False)  # Disable debug mode in production!

