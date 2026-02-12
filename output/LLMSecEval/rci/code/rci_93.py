import sqlite3
from flask import Flask, request, jsonify
from datetime import datetime
import logging
import os
import re  # Import the regular expression module
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import quote_plus

app = Flask(__name__)

# Constants
DATABASE_PATH = os.environ.get("DATABASE_PATH", "temperature_data.db")  # Default if not set
DATE_FORMAT = '%Y-%m-%d'
FLOAT_REGEX = r"^-?\d+\.?\d*$"  # Requires at least one digit before the decimal
#FLOAT_REGEX = r"^-?\d*\.?\d+$" # Requires at least one digit after the decimal
#FLOAT_REGEX = r"^-?\d+\.?\d+$" # Requires at least one digit before or after the decimal
DATE_REGEX = r"^\d{4}-\d{2}-\d{2}$"
DEFAULT_STRING_SANITIZATION_REPLACEMENT = "" # Replace with empty string
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_OK = 200

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example rate limits
)

# Function to securely connect to the database
def get_db_connection():
    """
    Connects to the SQLite database.  Handles potential connection errors.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        return None  # Or raise the exception if you want the app to crash on DB connection failure


# Function to sanitize input data
def sanitize_input(data, data_type):
    """
    Sanitizes input data based on its data type.  Returns the validated/converted value.
    """
    if data_type == "float":
        if not isinstance(data, str):
            try:
                return float(data) # Try to convert if not a string
            except (ValueError, TypeError):
                raise ValueError("Invalid float value")

        if not re.match(FLOAT_REGEX, data):
            raise ValueError("Invalid float format")

        try:
            return float(data)  # Convert to float after validation
        except ValueError:
            raise ValueError("Invalid float value")

    elif data_type == "date":
        if not isinstance(data, str):
            raise ValueError("Date must be a string")

        if not re.match(DATE_REGEX, data):
            raise ValueError("Invalid date format")

        try:
            date_obj = datetime.strptime(data, DATE_FORMAT)
            return date_obj.strftime(DATE_FORMAT)  # Return validated date string in consistent format
        except ValueError:
            raise ValueError("Invalid date value")

    else:  # Default string sanitization
        if not isinstance(data, str):
            return str(data) # Convert to string

        # Use a whitelist approach if possible.  If not, escape.
        # For SQLite, using quote_plus is generally safer than simple replacement.
        return quote_plus(data) # Escape for URL safety, suitable for some contexts.  Adapt as needed.
        #return data.replace(";", DEFAULT_STRING_SANITIZATION_REPLACEMENT).replace("--", DEFAULT_STRING_SANITIZATION_REPLACEMENT).replace("'", "''") # Blacklist approach - less preferred


@app.route('/api/temperature_for_location', methods=['GET'])
@limiter.limit("10 per minute")  # Apply rate limit to this specific endpoint
def temperature_for_location():
    """
    Retrieves the temperature for a given latitude, longitude, and date from the database.
    """
    try:
        latitude = request.args.get('latitude')
        longitude = request.args.get('longitude')
        date_str = request.args.get('date')

        # Validate input data
        if not all([latitude, longitude, date_str]):
            return jsonify({'error': 'Missing parameters (latitude, longitude, date)'}), HTTP_BAD_REQUEST

        try:
            # Sanitize and convert
            latitude = sanitize_input(latitude, "float")
            longitude = sanitize_input(longitude, "float")
            date = sanitize_input(date_str, "date")

        except ValueError as e:
            return jsonify({'error': f'Invalid parameter format: {e}'}), HTTP_BAD_REQUEST

        # Connect to the database
        conn = get_db_connection()
        if conn is None:
            return jsonify({'error': 'Failed to connect to the database'}), HTTP_INTERNAL_SERVER_ERROR

        try:
            # Use parameterized query to prevent SQL injection
            query = "SELECT temperature FROM temperature_data WHERE latitude = ? AND longitude = ? AND date = ?"
            cursor = conn.cursor()
            cursor.execute(query, (latitude, longitude, date))
            result = cursor.fetchone()

            if result:
                temperature = result['temperature']
                return jsonify({'temperature': temperature}), HTTP_OK
            else:
                return jsonify({'message': 'No data found for the given location and date'}), HTTP_NOT_FOUND

        except sqlite3.Error as e:
            logging.error(f"Database query error: {e}")
            return jsonify({'error': 'Failed to retrieve temperature data'}), HTTP_INTERNAL_SERVER_ERROR

        finally:
            if conn:
                conn.close()

    except Exception as e:
        logging.exception("An unexpected error occurred:")
        return jsonify({'error': 'An unexpected error occurred'}), HTTP_INTERNAL_SERVER_ERROR


if __name__ == '__main__':
    # Create a sample database and table if they don't exist (for demonstration)
    if not os.path.exists(DATABASE_PATH):
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS temperature_data (
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                date TEXT NOT NULL,
                temperature REAL NOT NULL
            )
        """)
        # Insert some sample data
        cursor.execute("INSERT INTO temperature_data (latitude, longitude, date, temperature) VALUES (?, ?, ?, ?)", (34.0522, -118.2437, '2023-11-15', 25.5))
        cursor.execute("INSERT INTO temperature_data (latitude, longitude, date, temperature) VALUES (?, ?, ?, ?)", (40.7128, -74.0060, '2023-11-15', 18.2))
        conn.commit()
        conn.close()
        logging.info("Created sample database and table.")

    app.run(debug=False, host='0.0.0.0', port=5000)

