# Example: CSRF Protection (using Flask-WTF)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24)  # Generate a CSRF secret key

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # ... your login logic ...
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

# In your login.html template:
# <form method="post">
#   {{ form.csrf_token }}
#   ... your form fields ...
# </form>

# Example: Error Logging
import logging

logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

@app.errorhandler(500)
def internal_server_error(error):
    logging.exception("Internal Server Error")  # Log the exception
    return "An internal server error occurred.", 500

# Example: Safe X-Forwarded-For Handling (requires trusted proxy configuration)
def get_client_ip():
    if 'X-Forwarded-For' in request.headers:
        # Only trust X-Forwarded-For if your proxy is configured to strip untrusted headers!
        return request.headers.getlist('X-Forwarded-For')[0]  # Get the first IP in the list
    else:
        return request.remote_addr

# Example: Content Security Policy (CSP)
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Basic CSP
    return response

