from flask import Flask, request, logging, make_response, session, redirect, url_for, render_template
import re
import os
from functools import wraps
import bcrypt  # For password hashing
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required as flask_login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Configuration for rate limiting (example)
REQUEST_LIMIT = 10
REQUEST_WINDOW = 60  # seconds
user_request_counts = {}

# Authentication (example - replace with a robust solution)
# NEVER store passwords in plain text! Use hashing.
ADMIN_USER = "admin"
#ADMIN_PASSWORD = "secure_password"  # Replaced with hashed password
ADMIN_PASSWORD_HASH = bcrypt.hashpw("secure_password".encode('utf-8'), bcrypt.gensalt())

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Where to redirect unauthenticated users

# CSRF Protection
csrf = CSRFProtect(app)

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def verify_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash)

# Dummy user database (replace with a real database)
users = {
    1: User(1, ADMIN_USER, ADMIN_PASSWORD_HASH)
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

# Helper function for rate limiting
def is_rate_limited(user_id):
    """Checks if a user has exceeded the request limit."""
    if user_id not in user_request_counts:
        user_request_counts[user_id] = []

    import time
    now = time.time()
    user_request_counts[user_id] = [ts for ts in user_request_counts[user_id] if ts > now - REQUEST_WINDOW]

    if len(user_request_counts[user_id]) >= REQUEST_LIMIT:
        return True
    else:
        user_request_counts[user_id].append(now)
        return False

# Authentication decorator (using Flask-Login)
# def login_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'username' not in session:
#             return redirect(url_for('login'))
#         return f(*args, **kwargs)
#     return decorated_function

# Login Form using Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = next((user for user in users.values() if user.username == username), None)

        if user and user.verify_password(password):
            login_user(user)
            return redirect(url_for('logdata'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html', form=form)

@app.route('/logout')
@flask_login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/logging')
@flask_login_required
def logdata():
    """
    Get the user name from the request using 'name' and log it if it not admin.
    """
    # Validate the request method
    if request.method != 'GET':
        return "Method not allowed", 405

    # Rate limiting
    user_id = request.remote_addr  # Use IP address for rate limiting (consider user ID after authentication)
    if is_rate_limited(user_id):
        return "Too many requests", 429

    name = request.args.get('name')

    # Input validation:  Strict allowlist for 'name'
    if name:
        if not re.match(r"^[a-zA-Z0-9_]+$", name):  # Allow only alphanumeric characters and underscores
            logging.warning(f"Invalid username format: {name}")
            return "Invalid username format. Only alphanumeric characters and underscores are allowed.", 400

        # Authorization: Check if the user is an admin
        #if session.get('username') != ADMIN_USER:
        if current_user.username != ADMIN_USER:
            logging.info(f"User accessed with name: {name}")
        else:
            logging.info("Admin user activity.")

    # Create a response
    response = make_response(f"Logged data (if applicable).  Hello, {name}!")
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0' # Disable caching

    # Set HttpOnly flag for session cookie
    session.modified = True # Ensure the session cookie is sent even if not modified

    return response

if __name__ == '__main__':
    # Important Security Considerations:
    # 1.  CSRF Protection:  Implement CSRF protection for all forms.  CSRF (Cross-Site Request Forgery) is an attack where a malicious website tricks a user's browser into performing an unwanted action on a trusted site where the user is authenticated.  A CSRF token is a secret, unique, and unpredictable value generated by the server and included in forms.  When the form is submitted, the server verifies the token to ensure that the request originated from the legitimate form and not a malicious site.  Use Flask-WTF for easy CSRF protection.
    # 2.  Database Security:  Use a proper database and an ORM (e.g., SQLAlchemy).  Use parameterized queries to prevent SQL injection.
    # 3.  HTTPS:  Always use HTTPS in production.
    # 4.  Secret Key Management:  Store the secret key securely (e.g., environment variable).
    # 5.  Input Validation:  Validate all user input to prevent XSS, SQL injection, and other attacks.
    # 6.  Output Encoding:  Encode all output to prevent XSS attacks.
    # 7.  Error Handling:  Implement proper error handling to prevent sensitive information from being exposed.
    # 8.  Rate Limiting:  Implement rate limiting to prevent brute-force attacks and denial-of-service attacks.  Rate limit based on user ID after authentication.
    # 9.  Content Security Policy (CSP):  Implement a CSP to prevent XSS attacks.
    # 10. HTTP Headers:  Set appropriate HTTP headers (e.g., X-Frame-Options, X-Content-Type-Options, HSTS).
    # 11. Dependencies:  Keep your dependencies up to date.
    # 12. Regular Security Audits:  Conduct regular security audits.
    # 13. Disable Debug Mode in Production:  Never run with debug=True in production.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

