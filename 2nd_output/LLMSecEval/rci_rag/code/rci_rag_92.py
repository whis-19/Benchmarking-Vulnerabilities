from flask import Flask, request, jsonify, session, make_response
import mysql.connector
import os
import secrets
import re
from urllib.parse import quote
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from markupsafe import escape
import cfgrib
import xarray as xr  # cfgrib depends on xarray

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Cryptographically secure secret key

# Database configuration (move to environment variables in production)
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_USER = os.environ.get("DB_USER", "user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "password")
DB_NAME = os.environ.get("DB_NAME", "database")

# --- Security Measures ---

# 7.  Origin Header Check (CORS)
#     Configure CORS (Cross-Origin Resource Sharing) properly to restrict which origins can access your API.
#     This is typically done using a library like `flask-cors`.
CORS(app, resources={r"/api/*": {"origins": ["https://yourdomain.com", "https://anotherdomain.com"]}})  # Replace with your allowed origins

# 9.  Rate Limiting
#     Implement rate limiting to prevent abuse.  Libraries like `Flask-Limiter` can help.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Example limits
    storage_uri="memory://"  # Use a persistent storage (e.g., Redis) in production
)

# --- Logging ---
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


# 1. CSRF Protection (using Flask-WTF or similar is recommended for more robust protection)
#    This example uses double-submitted cookies.  Flask-WTF provides more comprehensive CSRF protection.
def generate_csrf_token():
    return secrets.token_hex(16)

@app.before_request
def before_request():
    if request.method == 'POST':
        csrf_token = request.cookies.get('csrf_token')
        form_csrf_token = request.form.get('csrf_token')

        if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
            return jsonify({'error': 'CSRF token validation failed'}), 400

@app.after_request
def after_request(response):
    if 'csrf_token' not in session:
        csrf_token = generate_csrf_token()
        session['csrf_token'] = csrf_token
        response.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict') # HttpOnly and SameSite
    return response


# 2. Input Validation and Sanitization (Stringent Allowlist)
def sanitize_input(input_string, allowed_pattern):
    """
    Sanitizes input using a stringent allowlist.

    Args:
        input_string: The string to sanitize.
        allowed_pattern: A regular expression defining the allowed characters.

    Returns:
        The sanitized string, or None if the input is invalid.
    """
    if not re.match(allowed_pattern, input_string):
        return None  # Or raise an exception, depending on your needs
    return input_string

# 3.  XSS Prevention (using template engine's auto-escaping)
#     Flask's Jinja2 template engine automatically escapes variables by default,
#     preventing XSS attacks.  When constructing HTML dynamically, use `escape()` or `Markup()`
#     from `markupsafe` to ensure proper escaping.  For JSON responses, `jsonify` handles escaping.

# 4.  SQL Injection Prevention (using parameterized queries)
#     The `mysql.connector` library uses parameterized queries, which prevent SQL injection.
#     Never use string formatting to build SQL queries.

# 5.  HTTP Referer Check (Optional, but can be bypassed)
def validate_referer(request):
    """
    Validates the HTTP Referer header.  This is not foolproof, as the Referer can be spoofed.
    Use with caution and in conjunction with other security measures.
    """
    referer = request.headers.get('Referer')
    if not referer:
        logging.warning("Referer header missing")
        return False

    # Example: Check if the referer is from your own domain
    if not referer.startswith("https://yourdomain.com"):  # Replace with your domain
        logging.warning(f"Invalid Referer: {referer}")
        return False

    return True

# 6.  GET for State Changes (Discouraged for this API, but included for completeness)
#     This API is designed to retrieve data, so GET is appropriate.  If you were to *change* data,
#     use POST, PUT, PATCH, or DELETE.


# 8.  Error Handling
#     Avoid leaking sensitive information in error messages.  Log errors securely.

# 10. HTTPS
#      Ensure your application is served over HTTPS to encrypt all traffic.

# --- API Endpoint ---

@app.route('/api/temperature_for_location', methods=['POST'])  # Use POST for data submission
@limiter.limit("10/minute")  # Apply rate limiting to this endpoint
def get_temperature():
    """
    Retrieves the maximum temperature for a given location and time.
    """

    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400

    if not validate_referer(request):
        return jsonify({'error': 'Invalid Referer'}), 403

    data = request.get_json()

    # 1. Extract parameters from the request
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    year = data.get('year')
    month = data.get('month')
    day = data.get('day')
    grib_file = data.get('grib_file')

    # 2. Input Validation and Sanitization
    if not all([latitude, longitude, year, month, day, grib_file]):
        return jsonify({'error': 'Missing parameters'}), 400

    # Define allowed patterns for each parameter
    latitude_pattern = r"^-?\d+(\.\d+)?$"  # Example: -34.56
    longitude_pattern = r"^-?\d+(\.\d+)?$" # Example: 151.23
    year_pattern = r"^\d{4}$"  # Example: 2023
    month_pattern = r"^(0?[1-9]|1[0-2])$" # Example: 12 or 05
    day_pattern = r"^(0?[1-9]|[12][0-9]|3[01])$"   # Example: 31 or 08
    grib_file_pattern = r"^[a-zA-Z0-9._-]+\.grib$" # Example: data.grib.  More restrictive.

    latitude = sanitize_input(str(latitude), latitude_pattern)
    longitude = sanitize_input(str(longitude), longitude_pattern)
    year = sanitize_input(str(year), year_pattern)
    month = sanitize_input(str(month), month_pattern)
    day = sanitize_input(str(day), day_pattern)
    grib_file = sanitize_input(grib_file, grib_file_pattern)

    if not all([latitude, longitude, year, month, day, grib_file]):
        return jsonify({'error': 'Invalid parameters'}), 400

    try:
        # **CRITICAL: Use a GRIB parsing library to read the file safely**
        try:
            ds = xr.open_dataset(grib_file, engine="cfgrib")
        except Exception as e:
            logging.error(f"Error opening GRIB file: {e}")
            return jsonify({'error': 'Invalid GRIB file format'}), 400

        # **CRITICAL: Validate the data within the GRIB file**
        latitude = float(latitude)
        longitude = float(longitude)

        try:
            temperature = ds['t2m'].sel(latitude=latitude, longitude=longitude).values.item() # t2m is just an example
        except KeyError:
            logging.error("Latitude or longitude not found in GRIB file.")
            return jsonify({'error': 'Latitude or longitude not found in GRIB file.'}), 400
        except Exception as e:
            logging.error(f"Error accessing data in GRIB file: {e}")
            return jsonify({'error': 'Error accessing data in GRIB file'}), 500

        # **CRITICAL: Validate the temperature value**
        if not -100 < temperature < 100:  # Example range check
            logging.error(f"Temperature value out of range: {temperature}")
            return jsonify({'error': 'Temperature value out of range'}), 400

        # Escape the output for XSS protection
        temperature = escape(str(temperature))

        # 3. Database Connection and Query (Parameterized Query)
        try:
            connection = mysql.connector.connect(host=DB_HOST,
                                                 user=DB_USER,
                                                 password=DB_PASSWORD,
                                                 database=DB_NAME)
            cursor = connection.cursor()

            query = """
                SELECT max_temperature
                FROM temperature_data
                WHERE latitude = %s AND longitude = %s AND year = %s AND month = %s AND day = %s
            """
            cursor.execute(query, (latitude, longitude, year, month, day))
            result = cursor.fetchone()

            if result:
                max_temperature = result[0]
                # Escape the output for XSS protection, even though jsonify should handle it.  Defense in depth.
                max_temperature = escape(max_temperature)
                return jsonify({'max_temperature': max_temperature})
            else:
                return jsonify({'message': 'No data found for the given parameters'}), 404

        except mysql.connector.Error as err:
            logging.error(f"Database error: {err}")  # Log the error securely
            return jsonify({'error': 'Internal server error'}), 500

        except Exception as e:
            logging.exception("An unexpected error occurred") # Log the full exception
            return jsonify({'error': 'Internal server error'}), 500


        finally:
            if connection:
                cursor.close()
                connection.close()

        return jsonify({'temperature': temperature})

    except Exception as e:
        logging.exception("An unexpected error occurred")
        return jsonify({'error': 'Internal server error'}), 500

    finally:
        if 'ds' in locals():
            ds.close() # Close the dataset

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

