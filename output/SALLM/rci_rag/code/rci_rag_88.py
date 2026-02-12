from flask import Flask, request, make_response, session, render_template, redirect, url_for
from jinja2 import Environment, FileSystemLoader
import re
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
import logging
from datetime import timedelta
import unicodedata

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Initialize Jinja2 environment with autoescape enabled
loader = FileSystemLoader(searchpath="templates/")
env = Environment(loader=loader, autoescape=True)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# CSRF Protection
csrf = CSRFProtect(app)

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('error.html', error_message="Rate limit exceeded. Please try again later."), 429

@app.errorhandler(400)
def bad_request_handler(e):
    return render_template('error.html', error_message="Bad Request."), 400

@app.errorhandler(CSRFProtect.error_handler)
def csrf_error_handler(e):
    return render_template('error.html', error_message='CSRF Error: ' + e.description), 400

class NameForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=1, max=50),
                                           Regexp(r"^[a-zA-Z\s\.\'\-]*$",
                                                  message="Name must contain only letters, spaces, periods, hyphens, and apostrophes.")])
    submit = SubmitField('Submit')

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def index():
    form = NameForm()
    name = None

    if form.validate_on_submit():
        name = form.name.data
        # Normalize the input string to handle Unicode-based attacks
        name = unicodedata.normalize('NFKC', name).strip()
        logging.info(f"Name submitted: {name} from {request.remote_addr}")
        session['name'] = name  # Store the name in the session
        return redirect(url_for('hello'))

    return render_template('index.html', form=form, name=session.get('name'))

@app.route('/hello')
@limiter.limit("10 per minute")
def hello():
    name = session.get('name')
    if not name:
        return redirect(url_for('index'))

    template = env.get_template('hello.html')
    rendered_template = template.render(name=name)

    response = make_response(rendered_template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://analytics.example.com; style-src 'self' https://fonts.googleapis.com; img-src 'self' https://images.example.com data:; font-src 'self' https://fonts.gstatic.com; object-src 'none'; base-uri 'self'; report-uri /csp-report"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    return response

@app.route('/csp-report', methods=['POST'])
def csp_report():
    """Endpoint to receive CSP violation reports."""
    logging.warning(f"CSP Violation: {request.get_data(as_text=True)}")
    return '', 204

@app.route('/logout')
def logout():
    session.pop('name', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')

