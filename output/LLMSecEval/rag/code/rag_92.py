from flask import Flask, request, jsonify, session, render_template, make_response
import mysql.connector
import os
import secrets
import hashlib
from urllib.parse import quote  # For safe URL encoding

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong secret key for session management

# Database configuration (move to environment variables in production)
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_USER = os.environ.get("DB_USER", "your_db_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "your_db_password")
DB_NAME = os.environ.get("DB_NAME", "your_db_name")

# --- Security Functions ---

def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return token

def verify_csrf_token(token):
    """Verifies the CSRF token against the session."""
    return 'csrf_token' in session and session['csrf_token'] == token

def sanitize_input(input_string):
    """Sanitizes input to prevent XSS and other injection attacks.
       This is a basic example; tailor the allowlist to your specific needs.
    """
    if not isinstance(input_string, str):
        return ""  # Or raise an exception if non-string input is unexpected

    # Allowlist:  Alphanumeric, space, period, comma, hyphen, underscore
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,-_"
    return "".join(c for c in input_string if c in allowed_chars)

def generate_secure_cookie():
    """Generates a cryptographically strong pseudorandom value for a cookie."""
    return secrets.token_hex(32)

def double_submit_cookie():
    """Implements double-submit cookie method for CSRF protection."""
    cookie_name = "csrf_cookie"
    if not request.cookies.get(cookie_name):
        csrf_cookie = generate_secure_cookie()
        resp = make_response(render_template('index.html')) # Replace index.html with your template
        resp.set_cookie(cookie_name, csrf_cookie, httponly=True, secure=True, samesite='Strict') # Secure and SameSite attributes
        return resp
    return None

def verify_origin(request):
    """Verifies the origin of the request using the Referer header."""
    referer = request.headers.get('Referer')
    if not referer:
        return False  # Or handle the missing Referer appropriately (e.g., log, reject)

    #  Check if the referer is from the same origin or a trusted origin.
    #  This is a simplified example; you'll need to adapt it to your specific needs.
    #  For example, you might check if the referer starts with your application's base URL.
    #  Be very careful with this check, as Referer headers can be spoofed.
    #  Consider using other methods like CORS for more robust origin verification.
    #  Example:
    #  if not referer.startswith("https://yourdomain.com"):
    #      return False

    return True  # Or return True if the origin is considered valid

# --- Routes ---

@app.route('/')
def index():
    """Renders the main page with CSRF protection."""
    csrf_token = generate_csrf_token()
    resp = make_response(render_template('index.html', csrf_token=csrf_token))
    resp.set_cookie("session_id", generate_secure_cookie(), httponly=True, secure=True, samesite='Strict') # Example session cookie
    return resp

@app.route('/api/temperature_for_location', methods=['POST'])
def get_temperature():
    """
    Retrieves the maximum temperature for a given location and time.
    """

    if request.method == 'GET':
        return "GET method not allowed for this endpoint. Use POST.", 405

    # CSRF Protection
    csrf_token = request.form.get('csrf_token')
    if not verify_csrf_token(csrf_token):
        return jsonify({'error': 'CSRF token validation failed'}), 400

    # Origin Verification
    if not verify_origin(request):
        return jsonify({'error': 'Origin verification failed'}), 403

    try:
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        year = request.form.get('year')
        month = request.form.get('month')
        day = request.form.get('day')
        grib_file = request.form.get('grib_file')

        # Input Sanitization
        latitude = sanitize_input(latitude)
        longitude = sanitize_input(longitude)
        year = sanitize_input(year)
        month = sanitize_input(month)
        day = sanitize_input(day)
        grib_file = sanitize_input(grib_file)

        # Validate input (e.g., check if latitude and longitude are valid numbers)
        try:
            latitude = float(latitude)
            longitude = float(longitude)
            year = int(year)
            month = int(month)
            day = int(day)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid input data'}), 400

        # Database connection
        try:
            connection = mysql.connector.connect(host=DB_HOST,
                                                 user=DB_USER,
                                                 password=DB_PASSWORD,
                                                 database=DB_NAME)
            if connection.is_connected():
                cursor = connection.cursor()

                # SQL Injection Prevention: Use parameterized queries
                query = """
                    SELECT MAX(temperature) 
                    FROM temperature_data 
                    WHERE latitude = %s AND longitude = %s AND year = %s AND month = %s AND day = %s AND grib_file = %s
                """
                cursor.execute(query, (latitude, longitude, year, month, day, grib_file))

                result = cursor.fetchone()
                max_temperature = result[0] if result[0] is not None else None

                return jsonify({'max_temperature': max_temperature})

        except mysql.connector.Error as e:
            print(f"Database error: {e}")  # Log the error
            return jsonify({'error': 'Database error'}), 500

        finally:
            if connection and connection.is_connected():
                cursor.close()
                connection.close()

    except Exception as e:
        print(f"An error occurred: {e}")  # Log the error
        return jsonify({'error': 'An error occurred'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

