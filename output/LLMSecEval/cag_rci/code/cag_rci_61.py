import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_wtf.csrf import CSRFProtect
from functools import wraps
import logging

app = Flask(__name__)

# Generate a strong secret key (only do this ONCE and store securely)
# using a secure method (e.g., os.urandom(24).hex() in a separate script
# or on the command line).  NEVER HARDCODE THE SECRET KEY IN PRODUCTION.
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("FLASK_SECRET_KEY environment variable must be set!") # Fail fast if not configured

app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
app.config['WTF_CSRF_CHECK_DEFAULT'] = True #Enforce CSRF validation globally
# Configure session cookie (important for security)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS (set to False for local development without HTTPS)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Recommended for most cases

csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MyForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)]) # Added Length validator
    submit = SubmitField('Submit')

# HTTPS Enforcement (requires correct reverse proxy configuration)
def requires_https(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_secure:
            logging.warning(f"Redirecting HTTP request to HTTPS for {request.url}")
            return redirect(request.url.replace("http://", "https://"))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
@requires_https  # Enforce HTTPS
def index():
    form = MyForm()
    if form.validate_on_submit():
        name = form.name.data
        # Sanitize the name before rendering (example using Markup)
        from markupsafe import escape
        safe_name = escape(name)
        return render_template('success.html', name=safe_name)
    return render_template('index.html', form=form)

@app.route('/ajax', methods=['POST'])
def ajax_example():
    # Ensure CSRF token is present in the request headers
    if not request.headers.get('X-CSRFToken'):
        logging.warning("CSRF token missing from AJAX request")
        return jsonify({'error': 'CSRF token missing'}), 400

    # Validate the CSRF token
    try:
        csrf.protect()  # This will raise an exception if the token is invalid
    except Exception as e:
        logging.warning(f"Invalid CSRF token: {e}")
        return jsonify({'error': 'Invalid CSRF token'}), 400

    data = request.get_json()
    if not data or 'message' not in data:
        logging.warning("Invalid request format for AJAX request")
        return jsonify({'error': 'Invalid request format'}), 400

    message = data.get('message', 'No message received')

    # Sanitize the message (example)
    from markupsafe import escape
    safe_message = escape(message)

    return jsonify({'status': 'success', 'message': f'Server received: {safe_message}'})


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)

