import os
import secrets
import logging
from flask import Flask, render_template_string, request
import psycopg2  # Or your preferred database library
from flask_talisman import Talisman
import html
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Secure Configuration ---

# Generate a secure secret key for Flask sessions.  Do this *once* and store it
# securely (e.g., in an environment variable).  Do *not* generate a new key
# every time the application starts.
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    # This is only for initial setup.  Once you have a key, store it in an
    # environment variable.
    SECRET_KEY = secrets.token_hex(32)
    logger.warning(
        "No FLASK_SECRET_KEY environment variable found.  Generating a "
        "temporary key.  This is NOT SECURE for production.  Set the "
        "FLASK_SECRET_KEY environment variable to a long, random string."
    )

app.config["SECRET_KEY"] = SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = True  # Secure cookies for HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF

# --- Rate Limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# --- Database Configuration Functions ---

def get_db_server_name():
    """Returns the database server name from an environment variable."""
    server_name = os.environ.get("DB_SERVER_NAME")
    if not server_name:
        logger.error("DB_SERVER_NAME environment variable not set.")
        raise ValueError("DB_SERVER_NAME environment variable not set.")
    return server_name


def get_db_name():
    """Returns the database name from an environment variable."""
    db_name = os.environ.get("DB_NAME")
    if not db_name:
        logger.error("DB_NAME environment variable not set.")
        raise ValueError("DB_NAME environment variable not set.")
    return db_name


def get_db_user():
    """Returns the database user from an environment variable."""
    db_user = os.environ.get("DB_USER")
    if not db_user:
        logger.error("DB_USER environment variable not set.")
        raise ValueError("DB_USER environment variable not set.")
    return db_user


def get_db_password():
    """Returns the database password from an environment variable."""
    db_password = os.environ.get("DB_PASSWORD")
    if not db_password:
        logger.error("DB_PASSWORD environment variable not set.")
        raise ValueError("DB_PASSWORD environment variable not set.")
    return db_password


def get_db_connection():
    """Returns a database connection using environment variables.

    Raises:
        psycopg2.Error: If the connection fails.
    """
    try:
        conn = psycopg2.connect(
            host=get_db_server_name(),
            database=get_db_name(),
            user=get_db_user(),
            password=get_db_password(),
        )
        return conn
    except psycopg2.Error as e:
        logger.error(f"Database connection error: {e}")
        raise  # Re-raise the exception to be handled upstream


# --- Example Route ---
@app.route("/")
@limiter.limit("10 per minute")  # Example rate limit for this route
def hello_world():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version();")  # Example query
                db_version = cur.fetchone()[0]  # Fetch the version string
                db_version_escaped = html.escape(str(db_version))
                # Use Jinja2 templating for safer HTML rendering
                template = f"<p>Hello, World! Database version: {db_version_escaped}</p>"
                return render_template_string(template)
    except Exception as e:
        logger.exception("An error occurred while processing the request.")  # Log the full exception
        return "<p>An error occurred while processing your request.</p>"  # Generic message

# --- Example Route with Parameterized Query ---
@app.route("/user/<username>")
@limiter.limit("10 per minute")
def get_user(username):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                query = "SELECT * FROM users WHERE username = %s"
                cur.execute(query, (username,))  # Pass user input as a tuple
                user = cur.fetchone()
                if user:
                    user_escaped = html.escape(str(user)) # Escape the entire user tuple for safety
                    template = f"<p>User: {user_escaped}</p>"
                    return render_template_string(template)
                else:
                    return "<p>User not found.</p>"
    except Exception as e:
        logger.exception("Error fetching user.")
        return "<p>Error fetching user.</p>"

# --- Example Form and Route (with CSRF protection) ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

@app.route("/register", methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        hashed_password = generate_password_hash(password)

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    # Check if the username already exists
                    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                    existing_user = cur.fetchone()
                    if existing_user:
                        return "<p>Username already exists.</p>"

                    query = "INSERT INTO users (username, password) VALUES (%s, %s)"
                    cur.execute(query, (username, hashed_password))
                    conn.commit()
                    return "<p>Registration successful!</p>"
        except Exception as e:
            logger.exception("Error registering user.")
            return "<p>Error registering user.</p>"

    return render_template_string("""
        <form method="post">
            {{ form.csrf_token }}
            {{ form.username.label }} {{ form.username() }}<br>
            {{ form.password.label }} {{ form.password() }}<br>
            {{ form.submit() }}
        </form>
    """, form=form)

# --- CSP Report URI ---
@app.route('/csp_report', methods=['POST'])
def csp_report():
    # Process the CSP report (e.g., log it, send an email)
    logger.warning(f"CSP Violation: {request.get_json()}")
    return '', 204  # Return a 204 No Content response


# --- Security Headers ---
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Example: Allow scripts from a CDN
    'style-src': ['\'self\'', 'https://cdn.jsdelivr.net'],   # Example: Allow styles from a CDN
    'img-src': ['\'self\'', 'data:', '\'self\''],  # Allow images from your domain and data URIs
    'font-src': ['\'self\'', 'https://cdn.jsdelivr.net'], # Example: Allow fonts from a CDN
    'report-uri': '/csp_report',  # Endpoint to receive CSP reports
    'object-src': '\'none\'',
    'upgrade-insecure-requests': True
}

talisman = Talisman(app, content_security_policy=csp,
                    force_https=True,
                    frame_options='DENY',
                    content_type_options='nosniff',
                    referrer_policy='same-origin')


if __name__ == "__main__":
    # NEVER use debug=True in production.  It can expose sensitive information.
    # Use a production WSGI server (e.g., gunicorn, uWSGI) instead.
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

