import os
from flask import Flask, request, jsonify
import sqlite3
import logging
from datetime import datetime
from flask_cors import CORS
from functools import wraps  # For decorator
from urllib.parse import quote  # For URL encoding
import html  # For HTML escaping
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configuration from environment variables
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "https://example.com,https://anotherdomain.com").split(",")
CORS(app, origins=ALLOWED_ORIGINS)
DATABASE_NAME = os.environ.get("DATABASE_NAME", "Sensor.db")
DEBUG_MODE = os.environ.get("DEBUG", "False").lower() == "true"  # Convert to boolean
API_KEY = os.environ.get("API_KEY", "your_default_api_key")  # Replace with secure key management
ALLOWED_HOSTS_FOR_LOGGING = os.environ.get("ALLOWED_HOSTS_FOR_LOGGING", "example.com,127.0.0.1").split(",")  # For logging only, NOT authorization

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Example limits
    storage_uri="memory://"  # Use a persistent storage for production
)

# Authentication Decorator (Example - Replace with proper auth)
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key != API_KEY:
            logging.warning("Unauthorized access attempt")
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Input validation function (raises ValueError on failure)
def validate_input(latitude, longitude, date_str):
    try:
        latitude = float(latitude)
        longitude = float(longitude)
        if not (-90 <= latitude <= 90):
            raise ValueError("Invalid latitude")
        if not (-180 <= longitude <= 180):
            raise ValueError("Invalid longitude")

        date_object = datetime.strptime(date_str, '%Y-%m-%d')
        return latitude, longitude, date_object  # Return validated values

    except ValueError as e:
        raise ValueError(f"Invalid input: {e}") from None  # Re-raise with context

@app.route('/api/temperature_for_location', methods=['POST'])
@require_auth  # Apply authentication
@limiter.limit("10 per minute")  # Rate limit this endpoint
def temperature_for_location():
    try:
        data = request.get_json()
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        date = data.get('date')

        # Input validation
        try:
            latitude, longitude, date = validate_input(latitude, longitude, date)
        except ValueError as e:
            logging.warning(f"Invalid input: {e}")
            return jsonify({'error': str(e)}), 400

        # Database connection (using context manager for safety)
        with sqlite3.connect(DATABASE_NAME) as conn:
            cursor = conn.cursor()

            # Parameterized query to prevent SQL injection
            query = "SELECT temperature FROM TemperatureData WHERE latitude = ? AND longitude = ? AND date = ?"
            cursor.execute(query, (latitude, longitude, date.strftime('%Y-%m-%d'))) # Format date for query
            result = cursor.fetchone()

            if result:
                temperature = result[0]
                logging.info(f"Temperature found for location: {latitude}, {longitude}, {date}: {temperature}")
                return jsonify({'temperature': temperature}), 200
            else:
                logging.info(f"No temperature data found for location: {latitude}, {longitude}, {date}")
                return jsonify({'message': 'No data found for the given location and date'}), 404

    except Exception as e:
        logging.exception("An error occurred:")
        return jsonify({'error': 'An unexpected error occurred'}), 500  # Generic error message

if __name__ == '__main__':
    # Create the table if it doesn't exist (example)
    with sqlite3.connect(DATABASE_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS TemperatureData (
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                date TEXT NOT NULL,
                temperature REAL NOT NULL
            )
        """)
        # Create an index for faster lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_location_date ON TemperatureData (latitude, longitude, date)")
        conn.commit()

    # Enforce HTTPS in production (example - you'll need to configure SSL certificates)
    # app.run(debug=False, ssl_context=('path/to/cert.pem', 'path/to/key.pem'))
    # For development, you can run without SSL (but don't do this in production!)
    app.run(debug=DEBUG_MODE)

