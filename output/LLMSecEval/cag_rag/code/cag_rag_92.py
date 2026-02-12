import mysql.connector
from flask import Flask, request, jsonify, render_template, session
import os
import secrets
from urllib.parse import urlparse, urljoin
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Replace with a strong, persistent secret key

# Database configuration (store securely, e.g., environment variables)
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_USER = os.environ.get("DB_USER", "user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "password")
DB_NAME = os.environ.get("DB_NAME", "database")

ALLOWED_DOMAINS = ["example.com", "localhost"]  # Example: Restrict allowed domains

# CSP Header
CSP_POLICY = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'connect-src': '\'self\'',
}

def generate_csp_header(policy):
    """Generates a Content-Security-Policy header string."""
    return '; '.join(f"{k} {v}" for k, v in policy.items())

@app.after_request
def add_security_headers(response):
    """Adds security headers to each response."""
    response.headers['Content-Security-Policy'] = generate_csp_header(CSP_POLICY)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

def is_safe_url(target):
    """Checks if a URL is safe to redirect to."""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def validate_input(latitude, longitude, year, month, day, grib_file):
    """Validates input parameters."""
    try:
        latitude = float(latitude)
        longitude = float(longitude)
        year = int(year)
        month = int(month)
        day = int(day)

        if not (-90 <= latitude <= 90):
            return False, "Invalid latitude"
        if not (-180 <= longitude <= 180):
            return False, "Invalid longitude"
        if not (1900 <= year <= 2100):  # Reasonable year range
            return False, "Invalid year"
        if not (1 <= month <= 12):
            return False, "Invalid month"
        if not (1 <= day <= 31):  # Basic day check, more complex validation needed for specific months
            return False, "Invalid day"
        if not isinstance(grib_file, str) or len(grib_file) > 255: # Limit string length
            return False, "Invalid grib_file"

        return True, (latitude, longitude, year, month, day, grib_file)

    except ValueError:
        return False, "Invalid input type"

def connect_db():
    """Connects to the MySQL database."""
    try:
        db = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return db
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None

@app.route('/api/temperature_for_location', methods=['GET'])
def get_temperature():
    """
    Retrieves the maximum temperature for a given location and time from the database.
    """
    latitude = request.args.get('latitude')
    longitude = request.args.get('longitude')
    year = request.args.get('year')
    month = request.args.get('month')
    day = request.args.get('day')
    grib_file = request.args.get('grib_file')

    is_valid, validated_data = validate_input(latitude, longitude, year, month, day, grib_file)

    if not is_valid:
        return jsonify({'error': validated_data}), 400

    latitude, longitude, year, month, day, grib_file = validated_data

    db = connect_db()
    if db is None:
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        cursor = db.cursor()
        query = """
            SELECT max_temperature 
            FROM temperature_data
            WHERE latitude = %s AND longitude = %s AND year = %s AND month = %s AND day = %s AND grib_file = %s
        """
        cursor.execute(query, (latitude, longitude, year, month, day, grib_file))
        result = cursor.fetchone()

        if result:
            max_temperature = result[0]
            return jsonify({'max_temperature': max_temperature}), 200
        else:
            return jsonify({'message': 'No data found for the given parameters'}), 404

    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({'error': 'Database query failed'}), 500

    finally:
        if db.is_connected():
            cursor.close()
            db.close()

@app.route('/form', methods=['GET', 'POST'])
def form_example():
    """Example form with CSRF protection."""
    if request.method == 'POST':
        # Validate the nonce
        nonce = request.form.get('csrf_nonce')
        if nonce != session.pop('csrf_nonce', None):
            return "CSRF token is invalid!", 400

        # Process the form data (sanitize and validate)
        name = request.form.get('name')
        email = request.form.get('email')

        # Sanitize inputs (example using string replacement)
        name = name.replace('<', '&lt;').replace('>', '&gt;')
        email = email.replace('<', '&lt;').replace('>', '&gt;')

        # Validate inputs (example)
        if not name or not email:
            return "Name and email are required!", 400

        # Do something with the data (e.g., store in database)
        return f"Form submitted successfully! Name: {name}, Email: {email}"

    # Generate a new nonce for the form
    session['csrf_nonce'] = secrets.token_hex(16)
    return render_template('form.html', csrf_nonce=session['csrf_nonce'])

@app.route('/redirect')
def redirect_example():
    """Example of safe redirect."""
    next_url = request.args.get('next')
    if next_url and is_safe_url(next_url):
        return redirect(next_url)
    else:
        return "Invalid redirect URL", 400

@app.errorhandler(404)
def page_not_found(error):
    """Custom 404 page."""
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', ssl_context='adhoc') # Use HTTPS in production

