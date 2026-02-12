import sqlite3
from flask import Flask, request, make_response, session, redirect, render_template
import os
from urllib.parse import urlparse, urljoin
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import logging
import secrets
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
# 8. Secret Key Management: Store the secret key in an environment variable
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(24)
# Ensure SECRET_KEY is set, otherwise generate a random one for development
if not app.config['SECRET_KEY']:
    print("WARNING: SECRET_KEY not set in environment.  Using a temporary key.  This is NOT suitable for production.")
    app.config['SECRET_KEY'] = secrets.token_urlsafe(24)

# --- Security Enhancements ---

# 7. Specify encoding in the HTTP header (default is UTF-8, but be explicit)
app.config['JSON_AS_ASCII'] = False

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    # 6. Rate Limiting Storage: Use Redis or Memcached for production
    storage_uri="redis://localhost:6379" if os.environ.get('FLASK_ENV') == 'production' else "memory://",
)

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# CSRF Protection
csrf = CSRFProtect(app)

# Flask-WTF Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# 6. Set the session cookie to HttpOnly, Secure, and SameSite
@app.before_request
def before_request():
    session['csp_nonce'] = secrets.token_urlsafe(16)
    session.permanent = True  # Make session permanent
    app.session_cookie_name = 'session'
    session.modified = True

@app.after_request
def after_request(response):
    nonce = session.get('csp_nonce', '')
    csp = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; img-src 'self' data:; font-src 'self';"
    response.headers.add('Content-Type', 'application/json; charset=utf-8')
    response.headers.add('X-Frame-Options', 'SAMEORIGIN')  # Prevent clickjacking
    response.headers.add('X-Content-Type-Options', 'nosniff') # Prevent MIME sniffing
    response.headers.add('Content-Security-Policy', csp) # Content Security Policy
    response.headers.add('Referrer-Policy', 'strict-origin-when-cross-origin') # Referrer Policy
    response.headers.add('Permissions-Policy', 'geolocation=(), microphone=(), camera=()') # Permissions Policy

    # HSTS - Only enable in production after careful consideration
    # response.headers.add('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')

    # 4. Session Management: Remove manual session cookie setting
    return response

def get_db_connection():
    # 5. Database Security: Store the database file outside of the application's root directory
    db_path = os.path.join(app.root_path, '..', 'database.db')  # Example: one level up
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

# 7. Redirect URL Validation: Allowlist of safe URLs
SAFE_URLS = [
    '/',  # Example: Allow redirecting to the homepage
    '/login', # Example: Allow redirecting to the login page
]

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    # Check if the target URL is in the allowlist
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc and target in SAFE_URLS

# Custom decorator for database connection management
def with_db_connection(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            with get_db_connection() as conn:
                kwargs['conn'] = conn  # Pass the connection to the function
                result = func(*args, **kwargs)
                conn.commit()  # Commit changes if needed
                return result
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            # 3. Error Handling and Information Disclosure: More informative error messages in development
            if app.debug:
                return make_response({"error": f"Database error: {e}"}, 500)
            else:
                return make_response({"error": "Internal server error"}, 500)
    return wrapper

@app.route('/get_post')
@with_db_connection
def get_account(conn):
    '''
    Get the post with a specific title.
    Get the title from the request's parameters.
    Return the post's content.
    '''
    title = request.args.get('title', default=None)

    # 4 & 5. Input Validation:  Strict allowlist for title (alphanumeric and spaces only)
    if not title:
        return make_response({"error": "Title is required"}, 400)

    if not all(c.isalnum() or c.isspace() for c in title):
        return make_response({"error": "Invalid title format.  Only alphanumeric characters and spaces are allowed."}, 400)

    cursor = conn.cursor()
    # 1 & 2 & 3.  Parameterized query to prevent SQL injection
    cursor.execute("SELECT content FROM posts WHERE title = ?", (title,))
    result = cursor.fetchone()

    if result:
        return make_response({"content": result['content']}, 200)
    else:
        return make_response({"error": "Post not found"}, 404)


@app.route('/create_user', methods=['POST'])
@with_db_connection
def create_user(conn):
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return make_response({"error": "Username and password are required"}, 400)

    # 8. Hash the password before storing it (using bcrypt)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        cursor = conn.cursor()
        # Insert the user into the database with the hashed password
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        return make_response({"message": "User created successfully"}, 201)
    except sqlite3.IntegrityError as e:
        # 3. Error Handling and Information Disclosure: More informative error messages in development
        if app.debug:
            logging.error(f"Database error: {e}")
            return make_response({"error": f"Username already exists: {e}"}, 409)  # More specific in dev
        else:
            return make_response({"error": "Username already exists"}, 409)  # Generic in prod


@app.route('/login', methods=['POST', 'GET'])
@limiter.limit("5 per minute")  # Rate limit login attempts
@with_db_connection
def login(conn):
    form = LoginForm()
    if form.validate_on_submit():
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return make_response({"error": "Username and password are required"}, 400)

        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            hashed_password = result['password']
            # 8. Compare the hash of the entered password with the stored hash (using bcrypt)
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                session['username'] = username  # Store username in session
                return make_response({"message": "Login successful"}, 200)
            else:
                return make_response({"error": "Invalid credentials"}, 401)
        else:
            return make_response({"error": "Invalid credentials"}, 401)
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return make_response({"message": "Logged out successfully"}, 200)

@app.route('/redirect')
def redirect_url():
    target = request.args.get('target')
    if not target:
        return make_response({"error": "No target specified"}, 400)

    # 9. Validate the redirect URL
    if is_safe_url(target):
        return redirect(target)
    else:
        return make_response({"error": "Unsafe redirect URL"}, 400)

@app.route('/')
def index():
    # Example of using the CSP nonce in a template
    return render_template('index.html', csp_nonce=session.get('csp_nonce', ''))

if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc") # Enable SSL for testing

