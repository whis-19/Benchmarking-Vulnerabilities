import os
import logging
from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from cryptography.fernet import Fernet
import hashlib
import secrets
from functools import wraps
from datetime import timedelta

# Import WTForms
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length

# Import Flask-Talisman
from flask_talisman import Talisman

# Import Flask-Limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# -------------------- SECURITY CONFIGURATION --------------------

# 1. Encryption Key Management (CRITICAL)
#   - MUST be set as an environment variable.  NEVER hardcode or commit to source control.
#   - In production, use a proper secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager).
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    logging.error("FATAL: ENCRYPTION_KEY environment variable not set!")
    raise ValueError("ENCRYPTION_KEY environment variable must be set.")

#   - Generate a temporary key for development ONLY.  NEVER use this in production.
#   - Example: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
#   - DO NOT COMMIT THIS KEY TO SOURCE CONTROL.
DEVELOPMENT_ENCRYPTION_KEY = "YOUR_DEVELOPMENT_KEY_HERE"  # Replace with a generated key for development

# Choose the key based on the environment.  For simplicity, we're using an environment variable.
# A more robust approach would involve checking the Flask environment (e.g., `app.config['ENV'] == 'development'`).
if app.debug:
    encryption_key = DEVELOPMENT_ENCRYPTION_KEY.encode() # Encode to bytes
    logging.warning("WARNING: Using DEVELOPMENT_ENCRYPTION_KEY. DO NOT USE IN PRODUCTION!")
else:
    encryption_key = ENCRYPTION_KEY.encode() # Encode to bytes


fernet = Fernet(encryption_key)

# 2. Secret Key for Flask Sessions (CRITICAL)
#   - Used to sign session cookies.  MUST be strong and secret.
#   - Generate a random hex string: `python -c "import secrets; print(secrets.token_hex(16))"`
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(16)) # Fallback to a random key if not set
if app.config['SECRET_KEY'] == secrets.token_hex(16):
    logging.warning("WARNING: FLASK_SECRET_KEY environment variable not set. Using a randomly generated key.  This is NOT suitable for production.")

# 3. Session Timeout
#   - Automatically log users out after a period of inactivity.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Example: 30-minute timeout
app.config['SESSION_PERMANENT'] = True  # Make sessions permanent

# 4. Rate Limiting
#   - Protect against brute-force attacks on login and registration endpoints.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"], # Example: Global rate limit
    storage_uri="memory://" # Use a persistent storage for production (e.g., redis://localhost:6379)
)

# 5. Talisman Configuration (Security Headers)
#   - Enforces HTTPS, sets security headers (CSP, HSTS, X-Frame-Options, etc.).
talisman = Talisman(app,
                    content_security_policy={
                        'default-src': '\'self\'',
                        'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'], # Example: Allow scripts from a CDN
                        'style-src': ['\'self\'', 'https://cdn.jsdelivr.net']
                    },
                    force_https=True,  # Enforce HTTPS
                    session_cookie_secure=True) # Ensure session cookies are secure

# 6. CSRF Protection
#   - Protects against Cross-Site Request Forgery attacks.
#   - Requires Flask-WTF and a SECRET_KEY.
csrf = CSRFProtect(app)

# -------------------- DATABASE (In-Memory for Example) --------------------
# In a real application, use a proper database (e.g., PostgreSQL, MySQL).
users = {}

# -------------------- UTILITY FUNCTIONS --------------------

def hash_password(password):
    """Hashes the password using SHA-256 with a salt."""
    salt = secrets.token_hex(16)
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return salt, hashed_password

def verify_password(stored_salt, stored_hash, password):
    """Verifies the password against the stored hash and salt."""
    salted_password = stored_salt + password
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed_password == stored_hash

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# -------------------- WTForms --------------------

# Example WTForm
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# -------------------- ROUTES --------------------

@app.route('/')
def index():
    return "Welcome!  This is a secure application."

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Rate limit registration attempts
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        if username in users:
            return "Username already exists", 400

        salt, hashed_password = hash_password(password)
        users[username] = {'email': email, 'salt': salt, 'hashed_password': hashed_password}
        logging.info(f"User registered: {username}")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username not in users:
            return "Invalid username or password", 401

        user = users[username]
        if verify_password(user['salt'], user['hashed_password'], password):
            session['username'] = username
            logging.info(f"User logged in: {username}")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('profile'))
        else:
            return "Invalid username or password", 401
    return render_template('login.html', form=form)


@app.route('/profile')
@login_required
def profile():
    username = session['username']
    user = users[username]
    return render_template('profile.html', username=username, email=user['email'])


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


# -------------------- ERROR HANDLING --------------------

@app.errorhandler(404)
def page_not_found(e):
    return "Page not found", 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")  # Log the exception
    return "Internal Server Error", 500


# -------------------- MAIN --------------------

if __name__ == '__main__':
    #  NEVER enable debug mode in production.
    app.run(debug=True, host='0.0.0.0', port=5000)

