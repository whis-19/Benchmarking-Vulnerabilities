import json
import mysql.connector
from flask import Flask, request, jsonify
import os
from dotenv import load_dotenv
import logging
import re  # Import the regular expression module
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import secrets
import hashlib

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
#CORS(app)  # Enable CORS for all routes and origins (for development - restrict in production)
CORS(app, origins=["http://localhost:3000"]) # Example production CORS

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (read from environment variables)
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

# API Key (Example - Replace with a more robust authentication mechanism)
#API_KEY = os.getenv("API_KEY")
#if not API_KEY:
#    logging.warning("API_KEY environment variable not set.  Authentication is disabled.")

# Load API keys from environment variable (comma-separated)
API_KEYS = os.getenv("API_KEYS")
if not API_KEYS:
    logging.warning("API_KEYS environment variable not set. Authentication is disabled.")
    api_keys = []
else:
    api_keys = [key.strip() for key in API_KEYS.split(",")]  # Split and strip whitespace

# Error handling decorator
def handle_errors(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.exception(f"An error occurred: {e}")
            return jsonify({"error": "Internal Server Error"}), 500
    return wrapper

def sanitize_filename(filename):
    """Sanitizes a filename by removing potentially harmful characters."""
    return re.sub(r"[^a-zA-Z0-9_\-.]", "", filename)


@app.route('/api/temperature_for_location', methods=['POST'])
@limiter.limit("10/minute")  # Specific limit for this endpoint
@handle_errors
def get_temperature():
    """
    Endpoint to retrieve the maximum temperature for a given location and date.
    Expects a JSON payload with latitude, longitude, year, month, day, and grib_file.
    """

    # Authentication (Example using API Key)
    #if API_KEY:  # Only check if API_KEY is configured
    #    api_key = request.headers.get('X-API-Key')
    #    if api_key != API_KEY:
    #        return jsonify({"error": "Unauthorized"}), 401

    if api_keys:  # Only check if API_KEYS is configured
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key not in api_keys:
            return jsonify({"error": "Unauthorized"}), 401


    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        latitude = data.get('latitude')
        longitude = data.get('longitude')
        year = data.get('year')
        month = data.get('month')
        day = data.get('day')
        grib_file = data.get('grib_file')

        # Validate input data
        if not all([latitude, longitude, year, month, day, grib_file]):
            return jsonify({"error": "Missing parameters"}), 400

        try:
            latitude = float(latitude)
            longitude = float(longitude)
            year = int(year)
            month = int(month)
            day = int(day)
        except ValueError as e:
            logging.warning(f"Invalid data type: {e}")
            return jsonify({"error": "Invalid data types for parameters"}), 400

        # Basic input validation (add more robust validation as needed)
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            return jsonify({"error": "Invalid latitude or longitude"}), 400
        if not (1900 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31):  # Adjust year range as needed
            return jsonify({"error": "Invalid year, month, or day"}), 400

        # Validate grib_file using a regular expression
        grib_file = sanitize_filename(grib_file) # Sanitize before validation
        if not re.match(r"^[a-zA-Z0-9_\-.]+\.grib2?$", grib_file):  # Example regex
            return jsonify({"error": "Invalid grib_file format"}), 400


    except Exception as e:
        logging.error(f"Error processing request data: {e}")
        return jsonify({"error": "Invalid request"}), 400

    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )

        if not connection.is_connected():
            logging.error("Failed to connect to the database.")
            return jsonify({"error": "Database connection error"}), 500

        cursor = connection.cursor()

        # Sanitize inputs using parameterized queries to prevent SQL injection
        query = """
            SELECT MAX(temperature) 
            FROM temperature_data
            WHERE latitude = %s AND longitude = %s AND year = %s AND month = %s AND day = %s AND grib_file = %s
        """
        values = (latitude, longitude, year, month, day, grib_file)

        cursor.execute(query, values)
        result = cursor.fetchone()

        if result:
            max_temperature = result[0]
            return jsonify({"max_temperature": max_temperature}), 200
        else:
            return jsonify({"message": "No data found for the given parameters"}), 404

    except mysql.connector.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database query error"}), 500

    except Exception as err:
        logging.exception(f"Unexpected error: {err}")  # Log the full traceback
        return jsonify({"error": "Internal server error"}), 500


    finally:
        if connection and connection.is_connected():  # Check if connection exists before calling methods
            cursor.close()
            connection.close()


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)  #  Set debug to False in production

