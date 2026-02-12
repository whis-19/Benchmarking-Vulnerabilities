from flask import Flask, request, make_response, escape, session, render_template_string, abort
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Regexp, Length
from functools import wraps
import time
import logging
import os
from werkzeug.middleware.proxy_fix import ProxyFix  # For handling reverse proxies

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()  # Generate a strong, random key
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Rate Limiting ---
RATE_LIMIT = 5  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds
user_rates = {}

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip_address = request.remote_addr  # Get IP address
        now = time.time()

        if ip_address not in user_rates:
            user_rates[ip_address] = []

        user_rates[ip_address] = [ts for ts in user_rates[ip_address] if now - ts < RATE_LIMIT_WINDOW]

        if len(user_rates[ip_address]) >= RATE_LIMIT:
            logger.warning(f"Rate limit exceeded for IP: {ip_address}")
            abort(429, description="Too many requests")  # HTTP 429 Too Many Requests

        user_rates[ip_address].append(now)
        return f(*args, **kwargs)
    return decorated_function

# --- Content Security Policy ---
@app.after_request
def add_csp_header(response):
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    response.headers['Content-Security-Policy'] = csp
    return response


class NameForm(FlaskForm):
    first_name = StringField('First Name', validators=[
        DataRequired(),
        Length(max=50, message="First name must be less than 50 characters"), # Add length validation
        Regexp(r'^[a-zA-Z\s]+$', message="Only letters and spaces allowed")
    ])
    submit = SubmitField('Submit')


@app.route('/', methods=['GET', 'POST'])
@rate_limit  # Apply rate limiting
def echo_name():
    form = NameForm()
    if form.validate_on_submit():
        first_name = form.first_name.data

        # --- Contextual Input Validation (Example - SQL Injection Prevention) ---
        #  This is a simplified example.  For real-world SQL injection prevention,
        #  use parameterized queries or an ORM.  This example is for demonstration only.
        if any(char in first_name.lower() for char in ['--', ';', '/*']):
            logger.warning(f"Potential SQL injection attempt: {first_name}")
            abort(400, description="Invalid input")  # Bad Request

        # Escape the input to prevent XSS
        escaped_name = escape(first_name)

        greeting = f'Greetings, {escaped_name}!'

        # Create a response
        response = make_response(greeting)

        # Set the content type to ensure proper encoding
        response.headers['Content-Type'] = 'text/html; charset=utf-8'

        return response
    else:
        if form.errors:
            logger.warning(f"Validation errors: {form.errors}")
            # Log the specific errors for debugging
            for field, errors in form.errors.items():
                for error in errors:
                    logger.warning(f"Field: {field}, Error: {error}")
            abort(400, description="Invalid input") # Bad Request

    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Name Form</title>
        </head>
        <body>
            <form method="POST">
                {{ form.csrf_token }}
                {{ form.first_name.label }} {{ form.first_name() }}
                {% if form.first_name.errors %}
                    <ul>
                    {% for error in form.first_name.errors %}
                        <li>{{ error }}</li>
                    {% endfor %}
                    </ul>
                {% endif %}
                {{ form.submit() }}
            </form>
        </body>
        </html>
    ''', form=form)


if __name__ == '__main__':
    # Use a production WSGI server (e.g., gunicorn, uWSGI) in production
    # Example: gunicorn --bind 0.0.0.0:5000 your_app:app

    # Handle reverse proxies (e.g., behind a load balancer)
    app.wsgi_app = ProxyFix(app.wsgi_app)

    app.run(debug=False, host='0.0.0.0', port=5000)  # Explicitly set host and port

