import sqlite3
from flask import Flask, request, jsonify
from datetime import datetime
import os
from urllib.parse import urlparse

app = Flask(__name__)

# Database Configuration
DATABASE_FILE = 'temperature_data.db'
MAX_DB_CONNECTIONS = 5  # Limit the number of database connections

# Allowed Domains/IPs (for URL validation - if needed for other API calls)
ALLOWED_DOMAINS = ['example.com', '127.0.0.1']  # Replace with your allowed domains

# Initialize database (create table if it doesn't exist)
def initialize_database():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS temperatures (
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            date TEXT NOT NULL,
            temperature REAL NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

initialize_database()

# Database Connection Pool (simple implementation)
class ConnectionPool:
    def __init__(self, max_connections, db_file):
        self.max_connections = max_connections
        self.db_file = db_file
        self.connections = []
        self.lock = threading.Lock()  # For thread safety if needed

    def get_connection(self):
        with self.lock:
            if len(self.connections) < self.max_connections:
                conn = sqlite3.connect(self.db_file)
                self.connections.append(conn)
                return conn
            else:
                #  Wait for a connection to become available (or raise an exception)
                #  A more robust solution would use a queue and a background thread
                #  to manage connections.  For simplicity, we'll just raise an error.
                raise Exception("Maximum database connections reached.")

    def release_connection(self, conn):
        with self.lock:
            if conn in self.connections:
                conn.close()
                self.connections.remove(conn)

connection_pool = ConnectionPool(MAX_DB_CONNECTIONS, DATABASE_FILE)


# Input Validation Function
def validate_input(latitude, longitude, date_str):
    try:
        latitude = float(latitude)
        longitude = float(longitude)
        datetime.strptime(date_str, '%Y-%m-%d')  # Validate date format
        return latitude, longitude, date_str
    except ValueError:
        return None, None, None

# URL Validation Function (if needed for other API calls)
def validate_url(url):
    try:
        result = urlparse(url)
        if result.netloc in ALLOWED_DOMAINS:
            return True
        return False
    except:
        return False


# Temperature Cache (simple dictionary)
temperature_cache = {}
import threading

@app.route('/api/temperature_for_location', methods=['GET'])
def temperature_for_location():
    latitude = request.args.get('latitude')
    longitude = request.args.get('longitude')
    date_str = request.args.get('date')

    # Input Validation
    latitude, longitude, date_str = validate_input(latitude, longitude, date_str)
    if latitude is None or longitude is None or date_str is None:
        return jsonify({'error': 'Invalid input parameters'}), 400

    # Cache Key
    cache_key = (latitude, longitude, date_str)

    # Check Cache
    if cache_key in temperature_cache:
        return jsonify({'temperature': temperature_cache[cache_key]})

    conn = None  # Initialize conn to None
    try:
        conn = connection_pool.get_connection()
        cursor = conn.cursor()

        # Parameterized Query
        query = "SELECT temperature FROM temperatures WHERE latitude = ? AND longitude = ? AND date = ?"
        cursor.execute(query, (latitude, longitude, date_str))
        result = cursor.fetchone()

        if result:
            temperature = result[0]
            # Update Cache
            temperature_cache[cache_key] = temperature
            return jsonify({'temperature': temperature})
        else:
            return jsonify({'message': 'Temperature data not found for the given location and date'}), 404

    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        if conn:
            connection_pool.release_connection(conn)  # Release the connection


if __name__ == '__main__':
    import threading
    app.run(debug=False, ssl_context='adhoc') # Use HTTPS.  'adhoc' is for development only.  Use proper certificates in production.

