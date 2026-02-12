import sqlite3
from flask import Flask, request, jsonify
from datetime import datetime
import logging
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (using environment variables for security)
DATABASE_PATH = os.environ.get("DATABASE_PATH", "temperature_data.db")  # Default if not set

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
def sanitize_input(data):
    """
    Sanitizes input data to prevent SQL injection and other vulnerabilities.
    This is a basic example; adapt it to your specific needs.
    """
    if isinstance(data, str):
        # Basic sanitization: remove potentially harmful characters
        return data.replace(";", "").replace("--", "").replace("'", "''")  # Escape single quotes for SQL
    return data


@app.route('/api/temperature_for_location', methods=['GET'])
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
            return jsonify({'error': 'Missing parameters (latitude, longitude, date)'}), 400

        try:
            latitude = float(latitude)
            longitude = float(longitude)
            date_obj = datetime.strptime(date_str, '%Y-%m-%d')  # Validate date format
            date = date_obj.strftime('%Y-%m-%d') # Convert back to string for consistency
        except ValueError as e:
            return jsonify({'error': f'Invalid parameter format: {e}'}), 400

        # Sanitize input data
        latitude = sanitize_input(latitude)
        longitude = sanitize_input(longitude)
        date = sanitize_input(date)

        # Connect to the database
        conn = get_db_connection()
        if conn is None:
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

