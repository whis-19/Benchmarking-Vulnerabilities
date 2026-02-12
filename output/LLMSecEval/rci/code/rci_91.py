import sqlite3
from flask import Flask, request, jsonify
import datetime
import logging
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach
from flask_cors import CORS
import uuid  # For correlation IDs
import json  # For structured logging

app = Flask(__name__)

# Configure logging
# Use JSON logging for structured logs
def configure_logging():
    """Configures logging to use JSON format and include correlation IDs."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # Set the desired logging level

    # Create a handler that outputs JSON
    handler = logging.StreamHandler()
    formatter = logging.Formatter('{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "correlation_id": "%(correlation_id)s"}')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Add a filter to inject the correlation ID into the log record
    class CorrelationIdFilter(logging.Filter):
        correlation_id = None  # Class-level variable to store the correlation ID

        def filter(self, record):
            record.correlation_id = CorrelationIdFilter.correlation_id
            return True

    correlation_filter = CorrelationIdFilter()
    logger.addFilter(correlation_filter)

configure_logging()


# Database file path (relative to the script's location)
DATABASE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'sensor.db') # Secure location outside web server root

# Ensure the directory exists
os.makedirs(os.path.dirname(DATABASE_FILE), exist_ok=True)

# Function to create the database and table if they don't exist
def create_database():
    """Creates the database and the temperature_data table if they don't exist."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Create the temperature_data table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS temperature_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                date TEXT NOT NULL,
                temperature REAL NOT NULL
            )
        ''')
        conn.commit()
        logging.info(json.dumps({"message": "Database and table created/checked successfully."}))
    except sqlite3.Error as e:
        logging.error(json.dumps({"message": f"Database creation/check failed: {e}"}))
    finally:
        if conn:
            conn.close()


# Call create_database to ensure the database exists when the app starts
create_database()

# Secret Key
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    logging.critical(json.dumps({"message": "FLASK_SECRET_KEY environment variable not set!  Using a weak default.  This is a SECURITY RISK!"}))
    app.config['SECRET_KEY'] = 'your_default_secret_key'  # Provide a weak default only if the env var is missing
else:
    logging.info(json.dumps({"message": "FLASK_SECRET_KEY loaded from environment."}))


# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,  # Rate limit based on IP address
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# CORS Configuration - Restrict to specific origins
CORS(app, origins=['https://your-frontend-domain.com', 'https://another-allowed-domain.com']) # Replace with your actual frontend domains


def validate_coordinates(latitude, longitude):
    """Validates that latitude and longitude are within valid ranges."""
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        return False, "Latitude or longitude out of range."
    return True, None


@app.before_request
def before_request():
    """Assigns a unique correlation ID to each request."""
    correlation_id = str(uuid.uuid4())
    logging.getLogger().filters[0].correlation_id = correlation_id
    logging.info(json.dumps({"message": f"Request received", "path": request.path, "method": request.method}))


@app.after_request
def after_request(response):
    """Logs the response status code after each request."""
    logging.info(json.dumps({"message": f"Request completed", "status_code": response.status_code}))
    return response


@app.route('/api/temperature_for_location', methods=['POST'])
@limiter.limit("10/minute") # Add a specific limit to this endpoint
def temperature_for_location():
    """
    Retrieves the temperature for a given location and date from the database.

    Expects a JSON payload with latitude, longitude, and date.
    Returns the temperature as a JSON response.
    """
    conn = None  # Initialize conn to None for proper cleanup
    try:
        data = request.get_json()

        if not data:
            logging.warning(json.dumps({"message": "No JSON payload received."}))
            return jsonify({'error': 'No JSON payload received'}), 400

        latitude = data.get('latitude')
        longitude = data.get('longitude')
        date_str = data.get('date')  # Date as a string (e.g., "YYYY-MM-DD")

        # Validate input data
        if not all([latitude, longitude, date_str]):
            logging.warning(json.dumps({"message": "Missing latitude, longitude, or date in the payload."}))
            return jsonify({'error': 'Missing latitude, longitude, or date'}), 400

        try:
            latitude = float(data['latitude'])
            longitude = float(data['longitude'])
        except (TypeError, ValueError):
            logging.warning(json.dumps({"message": "Invalid latitude or longitude type."}))
            return jsonify({'error': 'Invalid latitude or longitude type'}), 400

        latitude = float(bleach.clean(str(latitude))) # Sanitize and convert to float
        longitude = float(bleach.clean(str(longitude))) # Sanitize and convert to float

        is_valid, error_message = validate_coordinates(latitude, longitude)
        if not is_valid:
            logging.warning(json.dumps({"message": error_message}))
            return jsonify({'error': error_message}), 400


        try:
            date_obj = datetime.datetime.strptime(date_str, '%Y-%m-%d')  # Validate date format
            date_str = date_obj.strftime('%Y-%m-%d') # Ensure consistent date format
        except ValueError:
            logging.warning(json.dumps({"message": "Invalid date format."}))
            return jsonify({'error': 'Invalid date format'}), 400


        # Connect to the database
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Sanitize the input using parameterized query to prevent SQL injection
        cursor.execute(
            "SELECT temperature FROM temperature_data WHERE latitude = ? AND longitude = ? AND date = ?",
            (latitude, longitude, date_str)
        )

        result = cursor.fetchone()

        if result:
            temperature = result[0]
            logging.info(json.dumps({"message": f"Temperature found: {temperature} for location ({latitude}, {longitude}) on {date_str}"}))
            return jsonify({'temperature': temperature}), 200
        else:
            logging.info(json.dumps({"message": f"No temperature data found for location ({latitude}, {longitude}) on {date_str}"}))
            return jsonify({'message': 'No temperature data found for the given location and date'}), 404

    except sqlite3.Error as e:
        logging.error(json.dumps({"message": f"Database error: {e}"}))
        return jsonify({'error': 'An unexpected error occurred'}), 500 # Generic error message
    except Exception as e:
        logging.exception(json.dumps({"message": f"An unexpected error occurred: {e}"}))  # Log the full exception
        return jsonify({'error': 'An unexpected error occurred'}), 500 # Generic error message
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    # Example usage:  You might want to seed the database with some data for testing.
    # This is just an example and should be removed or modified for production.
    # It's better to have a separate script for database seeding.
    conn = None # Initialize conn to None for proper cleanup
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO temperature_data (latitude, longitude, date, temperature) VALUES (?, ?, ?, ?)",
                       (34.0522, -118.2437, '2023-11-15', 25.5))
        cursor.execute("INSERT INTO temperature_data (latitude, longitude, date, temperature) VALUES (?, ?, ?, ?)",
                       (40.7128, -74.0060, '2023-11-15', 18.2))
        conn.commit()
        logging.info(json.dumps({"message": "Example data inserted into the database."}))
    except sqlite3.Error as e:
        logging.error(json.dumps({"message": f"Error inserting example data: {e}"}))
    finally:
        if conn:
            conn.close()

    # Run the Flask app
    app.run(debug=True)  # Disable debug mode in production!

