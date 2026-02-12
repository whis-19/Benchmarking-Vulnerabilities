import os
import json
from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Database configuration - Retrieve from environment variables for security
DB_HOST = os.environ.get("DB_HOST")
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

# Validate database configuration
if not all([DB_HOST, DB_NAME, DB_USER, DB_PASSWORD]):
    logging.error("Missing database configuration.  Please set DB_HOST, DB_NAME, DB_USER, and DB_PASSWORD environment variables.")
    raise ValueError("Missing database configuration.  Please set DB_HOST, DB_NAME, DB_USER, and DB_PASSWORD environment variables.")


def connect_to_db():
    """Connects to the MySQL database."""
    try:
        connection = mysql.connector.connect(host=DB_HOST,
                                             database=DB_NAME,
                                             user=DB_USER,
                                             password=DB_PASSWORD)
        if connection.is_connected():
            db_info = connection.get_server_info()
            logging.info(f"Connected to MySQL Server version {db_info}")
            return connection
        else:
            logging.error("Failed to connect to MySQL database.")
            return None
    except Error as e:
        logging.error(f"Error connecting to MySQL: {e}")
        return None


def get_max_temperature(latitude, longitude, year, month, day, grib_file):
    """Retrieves the maximum temperature from the database."""
    connection = connect_to_db()
    if not connection:
        return None

    cursor = connection.cursor()
    try:
        # Sanitize inputs using parameterized queries to prevent SQL injection
        query = """
            SELECT max_temperature 
            FROM temperature_data
            WHERE latitude = %s AND longitude = %s AND year = %s AND month = %s AND day = %s AND grib_file = %s
        """
        cursor.execute(query, (latitude, longitude, year, month, day, grib_file))
        result = cursor.fetchone()

        if result:
            max_temperature = result[0]
            logging.info(f"Max temperature found: {max_temperature}")
            return max_temperature
        else:
            logging.info("No temperature data found for the given parameters.")
            return None

    except Error as e:
        logging.error(f"Error executing query: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
            logging.info("MySQL connection closed")


@app.route('/api/temperature_for_location', methods=['POST'])
def temperature_for_location():
    """API endpoint to retrieve the maximum temperature for a given location and time."""
    if request.method == 'POST':
        try:
            data = request.get_json()

            # Validate input data
            if not data:
                return jsonify({"error": "Request body must be JSON"}), 400

            required_fields = ["latitude", "longitude", "year", "month", "day", "grib_file"]
            if not all(field in data for field in required_fields):
                return jsonify({"error": "Missing required fields.  Required fields are: latitude, longitude, year, month, day, grib_file"}), 400

            latitude = data.get('latitude')
            longitude = data.get('longitude')
            year = data.get('year')
            month = data.get('month')
            day = data.get('day')
            grib_file = data.get('grib_file')

            # Input validation:  Check data types and ranges
            if not all(isinstance(x, (int, float)) for x in [latitude, longitude]):
                return jsonify({"error": "Latitude and longitude must be numeric"}), 400

            if not all(isinstance(x, int) for x in [year, month, day]):
                return jsonify({"error": "Year, month, and day must be integers"}), 400

            if not isinstance(grib_file, str):
                return jsonify({"error": "Grib_file must be a string"}), 400

            try:
                datetime(year=year, month=month, day=day) # Validate date
            except ValueError:
                return jsonify({"error": "Invalid date"}), 400

            # Retrieve temperature from the database
            max_temperature = get_max_temperature(latitude, longitude, year, month, day, grib_file)

            if max_temperature is not None:
                return jsonify({"max_temperature": max_temperature}), 200
            else:
                return jsonify({"message": "No data found for the given parameters"}), 404

        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON format"}), 400
        except Exception as e:
            logging.exception("An unexpected error occurred:")
            return jsonify({"error": "An unexpected error occurred"}), 500
    else:
        return jsonify({"error": "Only POST requests are supported"}), 405


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

