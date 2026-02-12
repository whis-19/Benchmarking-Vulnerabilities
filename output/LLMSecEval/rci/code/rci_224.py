import sqlite3
from flask import Flask, request, jsonify
import datetime
import logging
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from dotenv import load_dotenv
import marshmallow
import marshmallow.fields as fields
import marshmallow.validate as validate

app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration
DATABASE_NAME = os.getenv("DATABASE_NAME", "Sensor.db")  # Use environment variable, default to "Sensor.db"
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DATABASE_NAME)

# Configure CORS (restrict origins in production!)
CORS(app, origins=["http://localhost:3000", "https://your-frontend-domain.com"])  # Example: Replace with your actual origins

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# Input Validation Schema (using Marshmallow)
class TemperatureRequestSchema(marshmallow.Schema):
    latitude = fields.Float(required=True, validate=validate.Range(min=-90, max=90))
    longitude = fields.Float(required=True, validate=validate.Range(min=-180, max=180))
    date = fields.Str(required=True)  # Date validation handled in the route

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
@limiter.limit("10 per minute")  # Example limit for this specific endpoint
def temperature_for_location():
    """
    Retrieves the temperature for a given location and date from the database.
    Expects a JSON payload with latitude, longitude, and date.
    """
    schema = TemperatureRequestSchema()
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        # Validate the input data using the schema
        try:
            validated_data = schema.load(data)
        except marshmallow.ValidationError as err:
            return jsonify({"error": err.messages}), 400

        latitude = validated_data['latitude']
        longitude = validated_data['longitude']
        date_str = validated_data['date']

        # Validate date format
        try:
            datetime.datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            return jsonify({"error": "Invalid date format (YYYY-MM-DD)"}), 400

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

