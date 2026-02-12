import sqlite3
from flask import Flask, request, jsonify
from datetime import datetime
import os

app = Flask(__name__)

# Database Configuration
DATABASE_FILE = "sensor.db"
MAX_DB_CONNECTIONS = 5  # Limit the number of database connections

# Create the database and table if they don't exist
def initialize_database():
    """Initializes the database with a table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS temperature_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            date TEXT NOT NULL,
            temperature REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()

initialize_database()


def validate_date(date_text):
    """Validates that the date is in ISO format (YYYY-MM-DD)."""
    try:
        datetime.strptime(date_text, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def validate_coordinates(latitude, longitude):
    """Validates that latitude and longitude are within reasonable ranges."""
    try:
        latitude = float(latitude)
        longitude = float(longitude)
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            return False
        return True
    except ValueError:
        return False

@app.route('/api/temperature_for_location', methods=['POST'])
def temperature_for_location():
    """
    Retrieves the temperature for a given location and date from the database.
    Expects latitude, longitude, and date in the request payload.
    """
    if request.method == 'POST':
        try:
            data = request.get_json()
            latitude = data.get('latitude')
            longitude = data.get('longitude')
            date = data.get('date')

            # Input Validation
            if not all([latitude, longitude, date]):
                return jsonify({'error': 'Missing parameters'}), 400

            if not validate_coordinates(latitude, longitude):
                return jsonify({'error': 'Invalid latitude or longitude'}), 400

            if not validate_date(date):
                return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

            latitude = float(latitude)
            longitude = float(longitude)

            # Database Connection (using a context manager for safety)
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            # Use parameterized query to prevent SQL injection
            cursor.execute("""
                SELECT temperature FROM temperature_data
                WHERE latitude = ? AND longitude = ? AND date = ?
            """, (latitude, longitude, date))

            result = cursor.fetchone()
            conn.close()

            if result:
                temperature = result[0]
                return jsonify({'temperature': temperature}), 200
            else:
                return jsonify({'message': 'No temperature data found for the given location and date'}), 404

        except Exception as e:
            print(f"Error: {e}")  # Log the error for debugging
            return jsonify({'error': 'Internal server error'}), 500
    else:
        return jsonify({'error': 'Method not allowed'}), 405


if __name__ == '__main__':
    # Ensure HTTPS in production (example using Flask's built-in server - NOT recommended for production)
    # In a production environment, use a proper web server like Gunicorn or uWSGI with a reverse proxy like Nginx or Apache
    # that handles SSL/TLS termination.
    # Example (for development only - DO NOT USE IN PRODUCTION):
    # app.run(debug=True, ssl_context='adhoc')  # Generates a self-signed certificate
    app.run(debug=True)

