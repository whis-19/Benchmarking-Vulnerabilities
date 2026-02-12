import sqlite3
from flask import Flask, request, jsonify
from datetime import datetime
import logging
import os
import re  # Import the regular expression module
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (using environment variables for security)
DATABASE_PATH = os.environ.get("DATABASE_PATH", "temperature_data.db")  # Default if not set

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
    Sanitizes input data based on its data type.
    """
    if data_type == "float":
        # Allow only digits, a decimal point, and a minus sign
        if isinstance(data, str):
            if not re.match(r"^-?\d*\.?\d*$", data):
                raise ValueError("Invalid float format")
            return float(data)  # Convert to float here for validation and return float
        elif isinstance(data, (int, float)):
            return float(data)
        else:
            raise ValueError("Invalid float format")
    elif data_type == "date":
        # Allow only YYYY-MM-DD format
        if isinstance(data, str):
            try:
                return datetime.strptime(data, '%Y-%m-%d').strftime('%Y-%m-%d') # Validate and return string
            except ValueError:
                raise ValueError("Invalid date format")
        else:
            raise ValueError("Invalid date format")
    else:  # Default string sanitization - AVOID IF POSSIBLE, use parameterized queries and output encoding instead
        if isinstance(data, str):
            return data.replace(";", "").replace("--", "").replace("'", "''")
        return str(data) # Convert to string for consistency - AVOID IF POSSIBLE


@app.route('/api/temperature_for_location', methods=['GET'])
@limiter.limit("10 per minute")  # Apply rate limit to this specific endpoint
def temperature_for_location():
    """
    Retrieves the temperature for a given latitude, longitude, and date from the database.
    """
    try:
        latitude_str = request.args.get('latitude')
        longitude_str = request.args.get('longitude')
        date_str = request.args.get('date')

        # Validate input data
        if not all([latitude_str, longitude_str, date_str]):
            return jsonify({'error': 'Missing parameters (latitude, longitude, date)'}), 400

        try:
            # Sanitize and convert
            latitude = sanitize_input(latitude_str, "float")
            longitude = sanitize_input(longitude_str, "float")
            date = sanitize_input(date_str, "date")

            # Range check for latitude and longitude
            if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                raise ValueError("Latitude/Longitude out of range")


        except ValueError as e:
            return jsonify({'error': f'Invalid parameter format: {e}'}), 400

        # Connect to the database
        conn = get_db_connection()
        if conn is None:
            logging.error("Failed to connect to the database")
            return jsonify({'error': 'Failed to connect to the database'}), 500

        try:
            # Use parameterized query to prevent SQL injection
            query = "SELECT temperature FROM temperature_data WHERE latitude = ? AND longitude = ? AND date = ?"
            cursor = conn.cursor()
            cursor.execute(query, (latitude, longitude, date))
            result = cursor.fetchone()

            if result:
                temperature = result['temperature']
                return jsonify({'temperature': temperature}), 200
            else:
                return jsonify({'message': 'No data found for the given location and date'}), 404

        except sqlite3.Error as e:
            logging.error(f"Database query error: {e}")
            return jsonify({'error': 'Failed to retrieve temperature data'}), 500

        finally:
            if conn:
                conn.close()

    except Exception as e:
        logging.exception("An unexpected error occurred:")
        return jsonify({'error': 'An unexpected error occurred'}), 500


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

