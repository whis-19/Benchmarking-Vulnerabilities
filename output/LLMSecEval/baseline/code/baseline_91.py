import sqlite3
from flask import Flask, request, jsonify
import datetime
import logging
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration
DATABASE_NAME = "Sensor.db"
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DATABASE_NAME)

# Function to create the database and table if they don't exist (run once)
def create_database():
    """Creates the database and the TemperatureData table if they don't exist."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Create the table with appropriate data types and constraints
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS TemperatureData (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                date TEXT NOT NULL,  -- Store date as text in ISO format (YYYY-MM-DD)
                temperature REAL NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Add an index for faster lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_location_date ON TemperatureData (latitude, longitude, date)")

        conn.commit()
        logging.info("Database and table created successfully.")
    except sqlite3.Error as e:
        logging.error(f"Error creating database: {e}")
    finally:
        if conn:
            conn.close()


# Example function to populate the database with some sample data (run once or periodically)
def populate_database():
    """Populates the database with some sample temperature data."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Sample data (replace with your actual data source)
        sample_data = [
            (34.0522, -118.2437, "2023-11-01", 25.5),  # Los Angeles
            (40.7128, -74.0060, "2023-11-01", 18.2),   # New York
            (51.5074, 0.1278, "2023-11-01", 12.8),    # London
            (34.0522, -118.2437, "2023-11-02", 26.1),  # Los Angeles
            (40.7128, -74.0060, "2023-11-02", 19.5)    # New York
        ]

        # Use parameterized queries to prevent SQL injection
        cursor.executemany("INSERT INTO TemperatureData (latitude, longitude, date, temperature) VALUES (?, ?, ?, ?)", sample_data)

        conn.commit()
        logging.info("Database populated with sample data.")
    except sqlite3.Error as e:
        logging.error(f"Error populating database: {e}")
    finally:
        if conn:
            conn.close()


# Create the database and populate it (only run these once or periodically)
create_database()
#populate_database()  #Uncomment to populate with sample data


@app.route('/api/temperature_for_location', methods=['POST'])
def temperature_for_location():
    """
    Retrieves the temperature for a given location and date from the database.
    Expects a JSON payload with latitude, longitude, and date.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        latitude = data.get('latitude')
        longitude = data.get('longitude')
        date_str = data.get('date')  # Date as string (YYYY-MM-DD)

        # Validate input data
        if not all([latitude, longitude, date_str]):
            return jsonify({"error": "Missing latitude, longitude, or date"}), 400

        try:
            latitude = float(latitude)
            longitude = float(longitude)
            datetime.datetime.strptime(date_str, '%Y-%m-%d')  # Validate date format
        except ValueError:
            return jsonify({"error": "Invalid latitude, longitude, or date format"}), 400

        # Database interaction
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()

            # Use parameterized query to prevent SQL injection
            cursor.execute("""
                SELECT temperature FROM TemperatureData
                WHERE latitude = ? AND longitude = ? AND date = ?
            """, (latitude, longitude, date_str))

            result = cursor.fetchone()

            if result:
                temperature = result[0]
                return jsonify({"temperature": temperature}), 200
            else:
                return jsonify({"message": "No temperature data found for the given location and date"}), 404

        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return jsonify({"error": "Database error"}), 500

        finally:
            if conn:
                conn.close()

    except Exception as e:
        logging.exception("An unexpected error occurred")  # Log the full exception
        return jsonify({"error": "An unexpected error occurred"}), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

