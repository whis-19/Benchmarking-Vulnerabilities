import sqlite3
from flask import Flask, request, jsonify
import datetime
import hashlib
import hmac
import os

app = Flask(__name__)

# Database Configuration
DATABASE_NAME = "Sensor.db"
MAX_DB_CONNECTIONS = 5  # Limit the number of database connections
db_connections = 0
DATABASE_USER = "readonly_user"  # User with read-only permissions
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")  # Store password securely in environment variable

# Secret key for message authentication (replace with a strong, randomly generated key)
SECRET_KEY = os.environ.get("MESSAGE_SECRET_KEY")  # Store secret key securely in environment variable
if not SECRET_KEY:
    raise ValueError("MESSAGE_SECRET_KEY environment variable must be set.")

# Function to get a database connection (with connection limiting)
def get_db_connection():
    global db_connections
    if db_connections >= MAX_DB_CONNECTIONS:
        raise Exception("Maximum database connections reached.")

    try:
        conn = sqlite3.connect(DATABASE_NAME)
        conn.row_factory = sqlite3.Row  # Access columns by name
        db_connections += 1
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None

# Function to close a database connection
def close_db_connection(conn):
    global db_connections
    if conn:
        conn.close()
        db_connections -= 1

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

# Function to generate a checksum for message integrity
def generate_checksum(message, secret_key):
    """Generates an HMAC-SHA256 checksum for the message."""
    key = secret_key.encode('utf-8')
    message_bytes = message.encode('utf-8')
    hmac_obj = hmac.new(key, message_bytes, hashlib.sha256)
    return hmac_obj.hexdigest()

# Function to verify the checksum
def verify_checksum(message, received_checksum, secret_key):
    """Verifies the HMAC-SHA256 checksum of the message."""
    expected_checksum = generate_checksum(message, secret_key)
    return hmac.compare_digest(expected_checksum, received_checksum)


# Cache for temperature data (example - can be improved with TTL)
temperature_cache = {}

@app.route('/api/temperature_for_location', methods=['POST'])
def temperature_for_location():
    """
    Retrieves the temperature for a given location and date from the database.
    Expects latitude, longitude, and date in the request payload.
    """
    try:
        data = request.get_json()

        # Validate input data (Guideline 9)
        if not data:
            return jsonify({"error": "Invalid request.  No data provided."}), 400

        latitude = data.get('latitude')
        longitude = data.get('longitude')
        date_str = data.get('date')
        checksum = data.get('checksum')  # Get the checksum from the request

        if not all([latitude, longitude, date_str, checksum]):
            return jsonify({"error": "Missing parameters (latitude, longitude, date, checksum)"}), 400

        if not validate_coordinates(latitude, longitude):
            return jsonify({"error": "Invalid latitude or longitude"}), 400

        if not validate_date(date_str):
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

        # Reconstruct the message for checksum verification
        message = f"{latitude}{longitude}{date_str}"

        # Verify the checksum (Guideline 8)
        if not verify_checksum(message, checksum, SECRET_KEY):
            return jsonify({"error": "Checksum verification failed.  Possible tampering."}), 400

        # Check the cache first (Guideline 4)
        cache_key = (latitude, longitude, date_str)
        if cache_key in temperature_cache:
            temperature = temperature_cache[cache_key]
            return jsonify({"temperature": temperature})

        # Database interaction (Guidelines 1, 2, 3, 5)
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Failed to connect to the database."}), 500

        try:
            cursor = conn.cursor()

            # Use parameterized query to prevent SQL injection (Guideline 2)
            query = "SELECT temperature FROM TemperatureData WHERE latitude = ? AND longitude = ? AND date = ?"
            cursor.execute(query, (latitude, longitude, date_str))
            result = cursor.fetchone()

            if result:
                temperature = result[0]
                # Store in cache (Guideline 4)
                temperature_cache[cache_key] = temperature
                return jsonify({"temperature": temperature})
            else:
                return jsonify({"message": "No temperature data found for the given location and date."}), 404

        except sqlite3.Error as e:
            print(f"Database query error: {e}")
            return jsonify({"error": "Failed to retrieve temperature data."}), 500
        finally:
            close_db_connection(conn)

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500


if __name__ == '__main__':
    # Create the database and table if they don't exist (for demonstration purposes)
    # In a real application, database setup should be done separately with appropriate permissions.
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS TemperatureData (
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            date TEXT NOT NULL,
            temperature REAL
        )
    """)
    conn.commit()
    conn.close()

    app.run(debug=False, host='0.0.0.0', port=5000)

