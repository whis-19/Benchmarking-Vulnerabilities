from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import logging
from urllib.parse import urlparse
from datetime import datetime
import os  # Import os for environment variables
from dotenv import load_dotenv  # Import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration from environment variable
DATABASE_NAME = os.getenv("DATABASE_NAME", 'Sensor.db')  # Default to Sensor.db if not set

# Allowed origins for CORS from environment variable
ALLOWED_DOMAINS_STR = os.getenv("ALLOWED_DOMAINS", 'http://127.0.0.1:5000')  # Default to localhost
ALLOWED_DOMAINS = ALLOWED_DOMAINS_STR.split(',')  # Split comma-separated string into a list

# CORS configuration - Allow all origins in development, specific origins in production
if app.debug:  # Check if Flask is in debug mode (usually development)
    CORS(app, resources={r"/api/*": {"origins": "*"}})  # Allow all origins in development - CAREFUL!
    logging.warning("CORS is configured to allow all origins in development mode.  This is NOT safe for production.")
else:
    CORS(app, resources={r"/api/*": {"origins": ALLOWED_DOMAINS}})

# Function to validate latitude and longitude
def validate_coordinates(latitude, longitude):
    """Validates latitude and longitude values."""
    try:
        latitude = float(latitude)
        longitude = float(longitude)
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            return False, "Latitude must be between -90 and 90, and longitude between -180 and 180."
        return True, None
    except ValueError:
        return False, "Latitude and longitude must be numeric values."

# Function to validate date format (YYYY-MM-DD)
def validate_date(date_str):
    """Validates date format (YYYY-MM-DD)."""
    try:
        date_obj = datetime.strptime(date_str, '%Y-%m-%d')
        if date_obj.date() > datetime.now().date():  # Check if date is in the future
            return False, "Date cannot be in the future."
        return True, None
    except ValueError:
        return False, "Invalid date format.  Use YYYY-MM-DD."

@app.route('/api/temperature_for_location', methods=['POST'])
def temperature_for_location():
    """
    Retrieves the temperature for a given location and date from the database.
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Invalid JSON payload'}), 400

        latitude = data.get('latitude')
        longitude = data.get('longitude')
        date_str = data.get('date')

        # Input validation
        valid_coords, coord_error = validate_coordinates(latitude, longitude)
        if not valid_coords:
            return jsonify({'error': coord_error}), 400

        valid_date, date_error = validate_date(date_str)
        if not valid_date:
            return jsonify({'error': date_error}), 400

        latitude = float(latitude)  # Convert to float after validation
        longitude = float(longitude)

        # Database interaction using parameterized query
        conn = None  # Initialize conn to None
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()

            # Parameterized query to prevent SQL injection
            query = "SELECT temperature FROM TemperatureData WHERE latitude = ? AND longitude = ? AND date = ?"
            cursor.execute(query, (latitude, longitude, date_str))
            result = cursor.fetchone()

            if result:
                temperature = result[0]
                return jsonify({'temperature': temperature}), 200
            else:
                return jsonify({'message': 'No data found for the given location and date.'}), 404

        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return jsonify({'error': 'Failed to retrieve temperature data.'}), 500
        finally:
            if conn:
                conn.close()

    except Exception as e:
        logging.exception("An unexpected error occurred:")
        return jsonify({'error': 'An unexpected error occurred.'}), 500

if __name__ == '__main__':
    # Create the table if it doesn't exist (example)
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS TemperatureData (
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            date TEXT NOT NULL,
            temperature REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()

    # Use HTTPS in production (example using Flask's built-in server - NOT RECOMMENDED FOR PRODUCTION)
    # In a production environment, use a proper web server like Gunicorn or uWSGI with a reverse proxy like Nginx or Apache
    # that handles SSL/TLS termination.
    # app.run(debug=True, ssl_context='adhoc')  # For development only - generates a self-signed certificate
    app.run(debug=True) # For development without HTTPS

