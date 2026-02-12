import secrets
import os
import logging
from flask import Flask, session, redirect, url_for, abort, render_template, request, flash
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect  # Import CSRFProtect
from markupsafe import escape  # For HTML escaping
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length

app = Flask(__name__)

# Secret Key (Environment Variable - Recommended)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
    print("Warning: No FLASK_SECRET_KEY environment variable set.  Using a generated key.  This is NOT recommended for production.")

# Session Configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Set to True in HTTPS environments
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # or 'Strict'

# CSRF Protection
csrf = CSRFProtect(app)  # Initialize CSRF protection

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Consider using rotating log files for production
# import logging.handlers
# handler = logging.handlers.RotatingFileHandler('app.log', maxBytes=1000000, backupCount=3)
# logging.getLogger('').addHandler(handler)

class MyForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=20)])
    submit = SubmitField('Submit')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = MyForm()
    if form.validate_on_submit():
        name = form.name.data
        # Sanitize the input (example: strip whitespace)
        name = name.strip()

        # HTML Escaping to prevent XSS
        safe_name = escape(name)

        # Further sanitization might be needed depending on the context
        # Example: If expecting an integer, use try/except and int()
        # Example: If interacting with a database, use parameterized queries to prevent SQL injection

        flash(f'Hello, {safe_name}!', 'success')  # Use the escaped name
        return render_template('index.html', form=form)
    return render_template('index.html', form=form)

@app.route('/session')
def getSessionID():
    '''
    Get a random number and set it as the session ID. Return the session ID.
    :return: The session ID.
    '''
    try:
        # Generate a cryptographically secure random session ID
        session_id = secrets.token_hex(16)  # Generate a 32-character hex string

        # Store the session ID in the session
        session['session_id'] = session_id
        session.permanent = True # Make the session permanent

        return str(session_id)
    except ValueError as ve:  # Example: Handle specific error types
        logging.error(f"ValueError generating session ID: {ve}")
        abort(400)  # Bad Request
    except Exception as e:
        logging.error(f"Error generating session ID: {e}")
        abort(500)  # Internal Server Error

@app.route('/logout')
def logout():
    session.pop('session_id', None) # Remove the session ID
    return "Logged out"

# Example route that requires CSRF protection (e.g., a form submission)
@app.route('/protected', methods=['POST'])
#@csrf.exempt #Remove this line if you are using forms.
def protected():
    # Process the form data here
    return "Form submitted successfully!"

@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f"Internal Server Error: {e}")
    return "Internal Server Error", 500

# Example of logging at different levels
logging.debug("This is a debug message")
logging.info("This is an info message")
logging.warning("This is a warning message")
logging.error("This is an error message")
logging.critical("This is a critical message")

if __name__ == '__main__':
    app.run(debug=False)

