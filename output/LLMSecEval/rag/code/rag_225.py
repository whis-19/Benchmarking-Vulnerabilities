import os
import secrets
import logging
from flask import Flask, request, jsonify, session, render_template, make_response
import mysql.connector
from urllib.parse import quote  # For safely quoting URL parameters

# Initialize Flask application
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong secret key for session management

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (read from environment variables)
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_USER = os.environ.get("DB_USER", "user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "password")
DB_NAME = os.environ.get("DB_NAME", "database")

# --- Security Measures ---

# 1. CSRF Protection (using Flask-WTF - example, adapt as needed)
#    Flask-WTF provides CSRF protection.  This example shows how to integrate it.
#    You'll need to install it: `pip install flask-wtf`
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField
from wtforms.validators import DataRequired, NumberRange

app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(32)  # CSRF secret key

class TemperatureForm(FlaskForm):
    latitude = StringField('Latitude', validators=[DataRequired()])
    longitude = StringField('Longitude', validators=[DataRequired()])
    year = IntegerField('Year', validators=[DataRequired(), NumberRange(min=1900, max=2100)])
    month = IntegerField('Month', validators=[DataRequired(), NumberRange(min=1, max=12)])
    day = IntegerField('Day', validators=[DataRequired(), NumberRange(min=1, max=31)])
    grib_file = StringField('Grib File', validators=[DataRequired()])


# 2. Input Validation and Sanitization (Allowlist and escaping)
def is_valid_latitude(latitude):
    try:
        lat = float(latitude)
        return -90 <= lat <= 90
    except ValueError:
        return False

def is_valid_longitude(longitude):
    try:
        lon = float(longitude)
        return -180 <= lon <= 180
    except ValueError:
        return False

def is_valid_year(year):
    try:
        year_int = int(year)
        return 1900 <= year_int <= 2100  # Reasonable year range
    except ValueError:
        return False

def is_valid_month(month):
    try:
        month_int = int(month)
        return 1 <= month_int <= 12
    except ValueError:
        return False

def is_valid_day(day):
    try:
        day_int = int(day)
        return 1 <= day_int <= 31  # Basic check, needs more context for specific month/year
    except ValueError:
        return False

def is_valid_grib_file(grib_file):
    # Implement a stricter allowlist based on your expected grib file naming convention.
    # This is a placeholder.  Replace with your specific requirements.
    allowed_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    return all(c in allowed_characters for c in grib_file)


# 3.  Prevent XSS (using Jinja2's autoescaping)
#     Flask uses Jinja2, which automatically escapes variables in templates, preventing XSS.
#     Always use templates to render dynamic content.

# 4.  HTTP Referer Check (Origin Verification)
def validate_origin(request):
    referer = request.headers.get('Referer')
    if not referer:
        logging.warning("Missing Referer header.")
        return False

    # Replace with your expected origin(s)
    allowed_origins = ["http://yourdomain.com", "https://yourdomain.com"]
    if any(origin in referer for origin in allowed_origins):
        return True
    else:
        logging.warning(f"Invalid Referer: {referer}")
        return False

# 5.  Double-Submitted Cookie (Example Implementation)
def generate_csrf_token():
    return secrets.token_hex(16)

@app.before_request
def before_request():
    if request.endpoint == 'get_temperature': # Apply to the API endpoint
        if request.method == 'POST':
            if not validate_origin(request):
                return jsonify({"error": "Invalid origin"}), 403

            csrf_token_header = request.headers.get('X-CSRF-Token')
            csrf_token_cookie = request.cookies.get('csrf_token')

            if not csrf_token_header or not csrf_token_cookie or csrf_token_header != csrf_token_cookie:
                logging.warning("CSRF token mismatch.")
                return jsonify({"error": "CSRF token mismatch"}), 403

@app.route('/get_csrf_token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf_token()
    resp = jsonify({'csrf_token': token})
    resp.set_cookie('csrf_token', token, httponly=True, secure=True, samesite='Strict') # Secure and Strict
    return resp

# --- API Endpoint ---
@app.route('/api/temperature_for_location', methods=['POST'])
def get_temperature():
    """
    Retrieves the maximum temperature for a given location and time from the database.
    """

    form = TemperatureForm(request.form)

    if not form.validate():
        return jsonify({"error": "Invalid form data", "details": form.errors}), 400

    latitude = form.latitude.data
    longitude = form.longitude.data
    year = form.year.data
    month = form.month.data
    day = form.day.data
    grib_file = form.grib_file.data

    # Input Validation
    if not (is_valid_latitude(latitude) and is_valid_longitude(longitude) and
            is_valid_year(year) and is_valid_month(month) and is_valid_day(day) and
            is_valid_grib_file(grib_file)):
        return jsonify({"error": "Invalid input parameters"}), 400

    try:
        # Connect to the database
        connection = mysql.connector.connect(host=DB_HOST,
                                             user=DB_USER,
                                             password=DB_PASSWORD,
                                             database=DB_NAME)
        cursor = connection.cursor()

        # SQL Injection Prevention: Use parameterized queries
        query = """
            SELECT max_temperature
            FROM temperature_data
            WHERE latitude = %s AND longitude = %s AND year = %s AND month = %s AND day = %s AND grib_file = %s
        """
        cursor.execute(query, (latitude, longitude, year, month, day, grib_file))

        result = cursor.fetchone()

        if result:
            max_temperature = result[0]
            return jsonify({"max_temperature": max_temperature})
        else:
            return jsonify({"message": "No data found for the given parameters"}), 404

    except mysql.connector.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500

    finally:
        if connection:
            cursor.close()
            connection.close()

# Example route to render a form with CSRF protection
@app.route('/', methods=['GET', 'POST'])
def index():
    form = TemperatureForm()
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    if form.validate_on_submit():
        # Process the form data (but in a real app, you'd likely redirect to the API endpoint)
        return render_template('result.html', data=form.data)

    resp = make_response(render_template('index.html', form=form, csrf_token=csrf_token))
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
    return resp

# Example template (index.html):
#  <form method="POST">
#      {{ form.csrf_token }}
#      {{ form.latitude.label }} {{ form.latitude }}
#      {{ form.longitude.label }} {{ form.longitude }}
#      {{ form.year.label }} {{ form.year }}
#      {{ form.month.label }} {{ form.month }}
#      {{ form.day.label }} {{ form.day }}
#      {{ form.grib_file.label }} {{ form.grib_file }}
#      <button type="submit">Submit</button>
#  </form>
#  <script>
#    const csrfToken = document.querySelector('input[name="csrf_token"]').value;
#    fetch('/api/temperature_for_location', {
#        method: 'POST',
#        headers: {
#            'Content-Type': 'application/x-www-form-urlencoded',
#            'X-CSRF-Token': csrfToken
#        },
#        body: new URLSearchParams(new FormData(document.querySelector('form')))
#    })
#    .then(response => response.json())
#    .then(data => console.log(data));
#  </script>

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)

