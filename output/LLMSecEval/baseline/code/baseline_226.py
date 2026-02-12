import sqlite3
from flask import Flask, request, jsonify
from datetime import datetime
import logging
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (using environment variables for security)
DATABASE_PATH = os.environ.get("DATABASE_PATH", "temperature_data.db")  # Default to a local file, but encourage env var
DATABASE_TIMEOUT = int(os.environ.get("DATABASE_TIMEOUT", 5)) # Default timeout, but allow override

# --- Database Setup (Run this once to create the database and table) ---
def initialize_database():
    """Initializes the database if it doesn't exist."""
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=DATABASE_TIMEOUT)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS temperatures (
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                date TEXT NOT NULL,
                temperature REAL NOT NULL,
                PRIMARY KEY (latitude, longitude, date)
            )
        """)
        conn.commit()
        conn.close()
        logging.info("Database initialized/checked successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
        raise  # Re-raise the exception to stop the application if DB init fails

initialize_database()


def get_db_connection():
    """Gets a database connection."""
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=DATABASE_TIMEOUT)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        return None  # Or raise an exception, depending on your error handling strategy


@app.route('/api/temperature_for_location', methods=['GET'])
def temperature_for_location():
    """
    Retrieves the temperature for a given latitude, longitude, and date from the database.
    """
    try:
        latitude = request.args.get('latitude', type=float)
        longitude = request.args.get('longitude', type=float)
        date_str = request.args.get('date', type=str)  # Expects date as string (YYYY-MM-DD)

        # Input validation
        if latitude is None or longitude is None or date_str is None:
            return jsonify({'error': 'Missing latitude, longitude, or date parameters'}), 400

        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()  # Validate date format
            date_str = str(date) # Convert back to string for database query consistency
        except ValueError:
            return jsonify({'error': 'Invalid date format.  Use YYYY-MM-DD.'}), 400

        # Database interaction
        conn = get_db_connection()
        if conn is None:
            return jsonify({'error': 'Failed to connect to the database'}), 500

        try:
            cursor = conn.cursor()
            cursor.execute("SELECT temperature FROM temperatures WHERE latitude = ? AND longitude = ? AND date = ?",
                           (latitude, longitude, date_str))  # Use parameterized query

            result = cursor.fetchone()

            if result:
                temperature = result[0]
                return jsonify({'temperature': temperature}), 200
            else:
                return jsonify({'message': 'Temperature data not found for the given location and date'}), 404

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
    # Example usage:  Populate the database with some sample data
    # This should be removed or protected in a production environment.
    # It's here for demonstration purposes only.
    def populate_sample_data():
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT OR IGNORE INTO temperatures (latitude, longitude, date, temperature) VALUES (?, ?, ?, ?)",
                               (34.0522, -118.2437, '2024-01-01', 20.0))  # Los Angeles
                cursor.execute("INSERT OR IGNORE INTO temperatures (latitude, longitude, date, temperature) VALUES (?, ?, ?, ?)",
                               (51.5074, 0.1278, '2024-01-01', 5.0))  # London
                conn.commit()
                logging.info("Sample data populated (if not already present).")
            except sqlite3.Error as e:
                logging.error(f"Error populating sample data: {e}")
            finally:
                conn.close()

    populate_sample_data()

    # Run the Flask app
    app.run(debug=False, host='0.0.0.0', port=5000)

