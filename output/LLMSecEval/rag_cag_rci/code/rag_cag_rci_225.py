from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import mysql.connector
import os
import secrets
from urllib.parse import urlparse
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Use a strong, randomly generated secret key

# Configuration (move to environment variables for production)
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_USER = os.environ.get("DB_USER", "your_db_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "your_db_password")
DB_NAME = os.environ.get("DB_NAME", "your_db_name")
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "example.com,localhost").split(",")  # Comma-separated list
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"  # Convert to boolean

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
    return 'Content-Security-Policy: ' + '; '.join(f"{k} {v}" for k, v in policy.items())

# Decorator to enforce allowed domains
def allowed_domain(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        origin = request.headers.get('Origin')
        if origin:
            parsed_origin = urlparse(origin)
            if parsed_origin.netloc not in ALLOWED_DOMAINS:
                return jsonify({"error": "Unauthorized domain"}), 403
        return func(*args, **kwargs)
    return wrapper

# Input Validation and Sanitization
def validate_input(data):
    """Validates and sanitizes input data."""
    try:
        latitude = float(data.get('latitude'))
        longitude = float(data.get('longitude'))
        year = int(data.get('year'))
        month = int(data.get('month'))
        day = int(data.get('day'))
        grib_file = str(data.get('grib_file'))  # Sanitize grib_file

        # Add more robust validation as needed (e.g., range checks)
        if not (-90 <= latitude <= 90):
            raise ValueError("Latitude must be between -90 and 90")
        if not (-180 <= longitude <= 180):
            raise ValueError("Longitude must be between -180 and 180")
        if not (2000 <= year <= 2100):  # Example year range
            raise ValueError("Year must be between 2000 and 2100")
        if not (1 <= month <= 12):
            raise ValueError("Month must be between 1 and 12")
        if not (1 <= day <= 31):
            raise ValueError("Day must be between 1 and 31")

        return latitude, longitude, year, month, day, grib_file
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid input: {e}")

# Database Connection (using a connection pool is recommended for production)
def get_db_connection():
    """Establishes a secure database connection."""
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            ssl_disabled=False, #Enforce SSL/TLS
            ssl_ca='path/to/your/ssl_certificate.pem' #Validate SSL/TLS certificate
        )
        return conn
    except mysql.connector.Error as e:
        print(f"Database connection error: {e}")
        return None

# Route to handle temperature requests
@app.route('/api/temperature_for_location', methods=['POST'])
@allowed_domain
def get_temperature():
    """
    Retrieves the maximum temperature for a given location and time from the database.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON data"}), 400

        latitude, longitude, year, month, day, grib_file = validate_input(data)

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        query = """
            SELECT MAX(temperature) 
            FROM temperature_data 
            WHERE latitude = %s AND longitude = %s AND year = %s AND month = %s AND day = %s AND grib_file = %s
        """
        values = (latitude, longitude, year, month, day, grib_file)

        cursor.execute(query, values)
        result = cursor.fetchone()

        cursor.close()
        conn.close()

        if result and result[0] is not None:
            max_temperature = result[0]
            return jsonify({"max_temperature": max_temperature}), 200
        else:
            return jsonify({"message": "No temperature data found for the given criteria"}), 404

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return jsonify({"error": "An internal server error occurred"}), 500

# Example form handling with CSRF protection (using Flask-WTF)
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField
from wtforms.validators import DataRequired, NumberRange

class TemperatureForm(FlaskForm):
    latitude = StringField('Latitude', validators=[DataRequired()])
    longitude = StringField('Longitude', validators=[DataRequired()])
    year = IntegerField('Year', validators=[DataRequired(), NumberRange(min=2000, max=2100)])
    month = IntegerField('Month', validators=[DataRequired(), NumberRange(min=1, max=12)])
    day = IntegerField('Day', validators=[DataRequired(), NumberRange(min=1, max=31)])
    grib_file = StringField('Grib File', validators=[DataRequired()])
    submit = SubmitField('Get Temperature')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = TemperatureForm()
    if form.validate_on_submit():
        # Process the form data (after CSRF validation)
        latitude = form.latitude.data
        longitude = form.longitude.data
        year = form.year.data
        month = form.month.data
        day = form.day.data
        grib_file = form.grib_file.data

        # Call the API endpoint (or perform database query directly)
        # ... (Implement the logic to call the /api/temperature_for_location endpoint or query the database)
        # For example:
        # response = requests.post(url_for('get_temperature', _external=True), json=form.data)
        # ...

        return render_template('result.html', latitude=latitude, longitude=longitude, year=year, month=month, day=day, grib_file=grib_file) #Escape all user input before rendering

    csp_header = generate_csp_header(CSP_POLICY)
    return render_template('index.html', form=form), 200, {'Content-Security-Policy': csp_header}

# Example result template (result.html)
# <h1>Temperature for Latitude: {{ latitude }}, Longitude: {{ longitude }}, Year: {{ year }}, Month: {{ month }}, Day: {{ day }}, Grib File: {{ grib_file }}</h1>
# <p>Result will be displayed here</p>

# Error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    app.run(debug=DEBUG, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS for all sensitive communications

