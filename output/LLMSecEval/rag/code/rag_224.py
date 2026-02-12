import sqlite3
from flask import Flask, request, jsonify
import datetime
import hashlib
import hmac
import os

app = Flask(__name__)

# Database Configuration
DATABASE = 'Sensor.db'
MAX_CONNECTIONS = 5  # Limit the number of database connections
connection_pool = []

# Secret key for message authentication (replace with a strong, randomly generated key)
SECRET_KEY = os.urandom(32)

# Function to get a database connection from the pool
def get_db_connection():
    if len(connection_pool) < MAX_CONNECTIONS:
        try:
            conn = sqlite3.connect(DATABASE)
            conn.row_factory = sqlite3.Row  # Access columns by name
            connection_pool.append(conn)
            return conn
        except sqlite3.Error as e:
            print(f"Database connection error: {e}")
            return None
    else:
        print("Maximum database connections reached.")
        return None

# Function to release a database connection back to the pool
def release_db_connection(conn):
    if conn:
        try:
            conn.close()
            if conn in connection_pool:
                connection_pool.remove(conn)
        except sqlite3.Error as e:
            print(f"Error closing database connection: {e}")

# Function to validate date format
def validate_date(date_text):
    try:
        datetime.datetime.strptime(date_text, '%Y-%m-%d')
        return True
    except ValueError:
        return False

# Function to validate latitude and longitude
def validate_coordinates(latitude, longitude):
    try:
        latitude = float(latitude)
        longitude = float(longitude)
        if -90 <= latitude <= 90 and -180 <= longitude <= 180:
            return True
        else:
            return False
    except ValueError:
        return False

# Function to generate a checksum for message authentication
def generate_checksum(message, timestamp):
    message_bytes = message.encode('utf-8')
    timestamp_bytes = str(timestamp).encode('utf-8')
    key = SECRET_KEY  # Use the secret key
    hmac_obj = hmac.new(key, message_bytes + timestamp_bytes, hashlib.sha256)
    return hmac_obj.hexdigest()

# Function to verify the checksum of a message
def verify_checksum(message, timestamp, checksum):
    expected_checksum = generate_checksum(message, timestamp)
    return hmac.compare_digest(checksum, expected_checksum)

@app.route('/api/temperature_for_location', methods=['POST'])
def temperature_for_location():
    """
    Retrieves the temperature for a given location and date from the database.
    Expects latitude, longitude, and date in the request payload.
    """
    try:
        data = request.get_json()

        # Validate input data
        if not data:
            return jsonify({'error': 'Invalid request: Missing JSON payload'}), 400

        latitude = data.get('latitude')
        longitude = data.get('longitude')
        date_str = data.get('date')

        if not all([latitude, longitude, date_str]):
            return jsonify({'error': 'Missing parameters: latitude, longitude, and date are required'}), 400

        if not validate_coordinates(latitude, longitude):
            return jsonify({'error': 'Invalid latitude or longitude'}), 400

        if not validate_date(date_str):
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

        # Time-sensitive message protection (replay attack prevention)
        timestamp = data.get('timestamp')
        checksum = data.get('checksum')

        if not timestamp or not checksum:
            return jsonify({'error': 'Missing timestamp or checksum for message authentication'}), 400

        try:
            timestamp = float(timestamp)
        except ValueError:
            return jsonify({'error': 'Invalid timestamp format'}), 400

        # Verify the checksum
        message = f"{latitude}{longitude}{date_str}"
        if not verify_checksum(message, timestamp, checksum):
            return jsonify({'error': 'Invalid checksum: Message authentication failed'}), 403  # Forbidden

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
                temperature = result[0]
                return jsonify({'temperature': temperature}), 200
            else:
                return jsonify({'message': 'No temperature data found for the given location and date'}), 404

        except sqlite3.Error as e:
            print(f"Database query error: {e}")
            return jsonify({'error': 'Failed to retrieve temperature data'}), 500
        finally:
            release_db_connection(conn)  # Release the connection back to the pool

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    # Create the table if it doesn't exist (example)
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
        except sqlite3.Error as e:
            print(f"Error creating table: {e}")
        finally:
            release_db_connection(conn)

    app.run(debug=False, host='0.0.0.0', port=5000)

