import subprocess
import sys
import os
from flask import Flask, request, render_template, session
from urllib.parse import urlparse
import tldextract
import re
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Regexp
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Configure CSRF protection
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configure session cookie flags
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection (more modern approach)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

ALLOWED_COMMANDS = ["ping"]  # Whitelist of allowed commands

class PingForm(FlaskForm):
    """
    Form for the ping functionality with CSRF protection and input validation.
    """
    url = StringField('URL', validators=[DataRequired(),
                                           Regexp(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
                                                  message="Invalid URL format")])  # More robust URL validation
    submit = SubmitField('Ping')

def execute_command(command, url):
    """
    Executes the specified command with the given URL.
    This function uses subprocess.run with proper quoting, escaping, and sanitization to prevent command injection.
    """
    try:
        # Construct the command with the quoted URL
        full_command = [command, "-c", "3", url]  # Limit to 3 pings

        # Execute the command using subprocess.run with shell=False for safety
        process = subprocess.run(full_command, capture_output=True, text=True, timeout=10, check=True)

        # Sanitize output to prevent information disclosure
        # Return only success or failure
        if process.returncode == 0:
            return "Ping successful."
        else:
            return "Ping failed."

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out for URL: {url}")
        return "Ping failed."
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with exit code {e.returncode} for URL: {url}\n{e.stderr}")
        return "Ping failed."  # Generic error message for the user
    except Exception as e:
        logger.exception(f"An unexpected error occurred for URL: {url}")
        return "Ping failed."  # Generic error message for the user

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Apply rate limiting to the ping route
def ping():
    """
    Handles the ping functionality.
    This function retrieves the URL from the form, validates it, and executes the ping command.
    """
    form = PingForm()
    output = ""

    if form.validate_on_submit():
        url = form.url.data
        command = "ping"  # Use the allowed command directly
        if command in ALLOWED_COMMANDS:
            logger.info(f"Executing ping command for URL: {url}")
            output = execute_command(command, url)
        else:
            output = "Error: Command not allowed."

    return render_template('ping.html', form=form, output=output)

@app.route('/set_session', methods=['POST'])
def set_session():
    """
    Example of storing data in the session.  This is not directly used in the ping functionality
    but demonstrates how to store data server-side instead of sending it to the client.
    """
    session['example_data'] = request.form.get('data')
    return "Session data set!"

@app.route('/get_session')
def get_session():
    """
    Example of retrieving data from the session.
    """
    data = session.get('example_data', 'No data in session')
    return f"Session data: {data}"

@app.errorhandler(429)
def ratelimit_error(e):
    return "Too many requests. Please try again later.", 429

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)  # Disable debugging in production

