import sqlite3
from flask import Flask, request, jsonify
from datetime import datetime
import os
from urllib.parse import urlparse, urlunparse

app = Flask(__name__)

# Database configuration
DATABASE_FILE = 'temperature_data.db'
MAX_DB_CONNECTIONS = 5  # Limit the number of database connections

# Create the database and table if they don't exist
def initialize_database():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS temperature_readings (
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            date TEXT NOT NULL,
            temperature REAL NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

initialize_database()

# Function to validate latitude and longitude
def validate_coordinates(latitude, longitude):
    try:
        latitude = float(latitude)
        longitude = float(longitude)
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            return False, "Latitude must be between -90 and 90, and longitude between -180 and 180."
        return True, (latitude, longitude)
    except ValueError:
        return False, "Invalid latitude or longitude format."

# Function to validate date format
def validate_date(date_str):
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True, date_str
    except ValueError:
        return False, "Invalid date format. Use YYYY-MM-DD."

# Function to sanitize URLs (basic example, expand as needed)
def sanitize_url(url):
    """
    Sanitizes a URL to prevent common injection attacks.
    This example focuses on removing potentially harmful characters
    and ensuring the URL is well-formed.  More sophisticated
    validation and sanitization might be needed depending on the
    specific application.
    """
    parsed_url = urlparse(url)

    # Remove potentially harmful characters from the path and query
    path = ''.join(c for c in parsed_url.path if c.isalnum() or c in '/._-')
    query = ''.join(c for c in parsed_url.query if c.isalnum() or c in '&=_-')

    # Reconstruct the URL with the sanitized components
    sanitized_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        path,
        parsed_url.params,
        query,
        parsed_url.fragment
    ))

    return sanitized_url

# Function to check allowed domains/IPs (example)
def is_allowed_domain(url, allowed_domains):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname in allowed_domains:
            return True
        return False
    except:
        return False

# Cache for database results (example)
temperature_cache = {}

@app.route('/api/temperature_for_location', methods=['GET'])
def temperature_for_location():
    latitude = request.args.get('latitude')
    longitude = request.args.get('longitude')
    date_str = request.args.get('date')

    # Input validation
    is_valid_coords, coords_or_error = validate_coordinates(latitude, longitude)
    if not is_valid_coords:
        return jsonify({'error': coords_or_error}), 400

    is_valid_date, date_or_error = validate_date(date_str)
    if not is_valid_date:
        return jsonify({'error': date_or_error}), 400

    latitude, longitude = coords_or_error
    date = date_or_error

    # Check cache
    cache_key = (latitude, longitude, date)
    if cache_key in temperature_cache:
        return jsonify({'temperature': temperature_cache[cache_key]})

    try:
        conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
        conn.row_factory = sqlite3.Row  # Access columns by name
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute(
            "SELECT temperature FROM temperature_readings WHERE latitude = ? AND longitude = ? AND date = ?",
            (latitude, longitude, date)
        )

        result = cursor.fetchone()

        if result:
            temperature = result['temperature']
            # Store result in cache
            temperature_cache[cache_key] = temperature
            return jsonify({'temperature': temperature})
        else:
            return jsonify({'message': 'No temperature data found for the given location and date.'}), 404

    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error
        return jsonify({'error': 'Failed to retrieve temperature data.'}), 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    # Example of setting allowed domains (expand as needed)
    allowed_domains = ["example.com", "127.0.0.1"]

    # Example of sanitizing a URL (expand as needed)
    example_url = "https://example.com/search?q=test&param=<script>alert('XSS')</script>"
    sanitized_url = sanitize_url(example_url)
    print(f"Original URL: {example_url}")
    print(f"Sanitized URL: {sanitized_url}")

    # Example of checking allowed domains
    url_to_check = "https://example.com/api/data"
    if is_allowed_domain(url_to_check, allowed_domains):
        print(f"URL {url_to_check} is from an allowed domain.")
    else:
        print(f"URL {url_to_check} is NOT from an allowed domain.")

    # Use HTTPS in production (example using Flask's development server is not secure)
    # In a production environment, use a proper web server like Gunicorn or uWSGI
    # and configure it to use HTTPS with a valid SSL/TLS certificate.
    app.run(debug=True, ssl_context='adhoc') # Use 'adhoc' for testing only.  NEVER in production.

