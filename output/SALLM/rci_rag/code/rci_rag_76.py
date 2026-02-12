from flask import Flask, request, session, render_template, redirect, url_for, make_response
import ast
import re
import os
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
import logging
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)  # Use environment variable for secret key, or generate a random one if not set

# Configure CSRF protection
class MathForm(FlaskForm):
    equation = StringField('Equation', validators=[DataRequired()])
    submit = SubmitField('Calculate')

# Configure session
app.permanent_session_lifetime = timedelta(minutes=30)  # Example session expiration

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example rate limits
)


# Set HttpOnly flag for session cookie
@app.after_request
def add_security_headers(resp):
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
    resp.set_cookie('session', session.get('session', ''), httponly=True, secure=True, samesite='Lax') # Secure and SameSite attributes
    return resp


@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Apply rate limit to the route
def index():
    form = MathForm()
    result = None

    if form.validate_on_submit():
        equation = form.equation.data

        # Input validation:  Allow only basic arithmetic operators and numbers.
        if not re.match(r"^[\d\s+\-*/().eE]+$", equation): # Added eE for scientific notation
            logging.warning(f"Invalid equation format submitted: {equation}")
            return render_template('index.html', form=form, result="Invalid equation format. Only numbers and basic arithmetic operators (+, -, *, /) are allowed.")

        try:
            # Use ast.literal_eval for safe evaluation
            result = ast.literal_eval(equation)
            result = str(result)  # Convert result to string for display
        except (ValueError, SyntaxError, TypeError) as e:
            logging.error(f"Invalid equation: {str(e)}")
            result = "Invalid equation." # Generic error message for the user
        except Exception as e:
            # Log the error for debugging purposes (in a real application, use a proper logging system)
            logging.exception("An unexpected error occurred:")  # Log the full exception
            result = "An error occurred while processing the equation."

    return render_template('index.html', form=form, result=result)


if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

