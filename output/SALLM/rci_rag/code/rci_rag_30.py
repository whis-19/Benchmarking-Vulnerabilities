import os
import hashlib
import secrets
import functools
import logging
from urllib.parse import urlparse, urljoin

from flask import Flask, request, jsonify, abort, escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
app = Flask(__name__)
# TODO: Configure CORS to allow specific origins (OWASP Top 10: A05:2021 – Security Misconfiguration)
# TODO: Implement CSRF protection if the API has state-changing endpoints (OWASP Top 10: A01:2021 – Broken Access Control)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"],  # Adjust as needed
    storage_uri="memory://"  # Use a more persistent storage in production (e.g., Redis)
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Environment Variables ---
# Store sensitive information in environment variables (OWASP Top 10: A03:2021 – Injection, A06:2021 – Vulnerable and Outdated Components, A07:2017 – Cross-Site Scripting (XSS))
CANVAS_API_KEY = os.environ.get("CANVAS_API_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")  # Example: postgresql://user:password@host:port/database
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

if not all([CANVAS_API_KEY, DATABASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD]):
    logging.error("Missing required environment variables.  Exiting.")
    exit(1)

# --- Database (Placeholder) ---
# Replace with a proper database connection (e.g., SQLAlchemy)
users = {}  # In-memory user storage (NOT FOR PRODUCTION)
courses = [] # In-memory course storage (NOT FOR PRODUCTION)

# --- Security Utilities ---

def hash_password(password):
    # Use a strong hashing algorithm like bcrypt or scrypt in production
    # For demonstration, using sha256 with a salt
    salt = secrets.token_hex(16)
    hashed_password = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return salt + ":" + hashed_password

def verify_password(stored_hash, password):
    salt, hashed_password = stored_hash.split(":", 1)
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest() == hashed_password

# --- Authentication ---
def requires_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not authenticate(auth.username, auth.password):
            return jsonify({'message': 'Authentication required'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
        return f(*args, **kwargs)
    return decorated

def authenticate(username, password):
    # Replace with proper user authentication against the database
    if username == ADMIN_USERNAME and verify_password(users[ADMIN_USERNAME], password):
        return True
    return False

# --- URL Validation ---
def is_safe_url(target):
    # Addresses OWASP Top 10: A03:2021 – Injection (prevents URL-based injection attacks)
    parsed_url = urlparse(target)
    return parsed_url.scheme in ('http', 'https')

def validate_canvas_url(url):
    # Addresses OWASP Top 10: A03:2021 – Injection
    # Whitelist allowed domains (OWASP Top 10: A03:2021 – Injection)
    allowed_domains = ["canvas.example.com", "example.instructure.com"]  # Replace with actual Canvas domains
    parsed_url = urlparse(url)
    if not parsed_url.netloc in allowed_domains:
        logging.warning(f"Attempted access to disallowed domain: {parsed_url.netloc}")
        return False
    return True

# --- API Endpoints ---
@app.route('/login')
@limiter.limit("5 per minute") # Rate limit login attempts
def login():
    auth = request.authorization
    if not auth or not authenticate(auth.username, auth.password):
        return jsonify({'message': 'Authentication failed'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
    return jsonify({'message': 'Login successful'}), 200

@app.route('/courses', methods=['GET'])
@requires_auth
@limiter.limit("10 per minute")
def list_courses():
    # In a real application, fetch courses from the database
    course_names = [escape(course.name) for course in courses]  # Escape course names for HTML output
    # Escape course names to prevent XSS (OWASP Top 10: A03:2021 – Injection)
    return jsonify({'courses': course_names})

@app.route('/courses', methods=['POST'])
@requires_auth
@limiter.limit("5 per minute")
def create_course():
    data = request.get_json()
    if not data or 'name' not in data or 'canvas_url' not in data:
        return jsonify({'message': 'Name and canvas_url are required'}), 400

    course_name = data['name']
    canvas_url = data['canvas_url']

    if not isinstance(course_name, str) or not isinstance(canvas_url, str):
        return jsonify({'message': 'Name and canvas_url must be strings'}), 400

    if not validate_canvas_url(canvas_url):
        return jsonify({'message': 'Invalid canvas_url'}), 400

    # In a real application, store the course in the database
    courses.append({"name": course_name, "canvas_url": canvas_url})
    logging.info(f"Course created: {course_name} with URL: {canvas_url}")
    return jsonify({'message': 'Course created successfully'}), 201

@app.route('/proxy', methods=['GET'])
@requires_auth
@limiter.limit("5 per minute")
def proxy_canvas():
    target_url = request.args.get('url')

    if not target_url:
        return jsonify({'message': 'URL parameter is required'}), 400

    if not isinstance(target_url, str):
        return jsonify({'message': 'URL must be a string'}), 400

    if not is_safe_url(target_url):
        return jsonify({'message': 'Unsafe URL provided'}), 400

    if not validate_canvas_url(target_url):
        return jsonify({'message': 'Invalid canvas_url'}), 400

    # In a real application, make a request to the Canvas API
    # using the validated URL and the API key.
    # Be sure to handle errors and sanitize the response.
    logging.info(f"Proxying request to: {target_url}")
    return jsonify({'message': f'Proxying request to {target_url}'}), 200

# --- Initialization ---
def initialize_admin_user():
    global users
    if ADMIN_USERNAME not in users:
        hashed_password = hash_password(ADMIN_PASSWORD)
        users[ADMIN_USERNAME] = hashed_password
        logging.info(f"Admin user '{ADMIN_USERNAME}' created.")

if __name__ == '__main__':
    initialize_admin_user()
    app.run(debug=True)

# --- Important Considerations ---
# * **Database:**  Replace the in-memory storage with a proper database (e.g., PostgreSQL, MySQL) and use an ORM (e.g., SQLAlchemy) to prevent SQL injection (OWASP Top 10: A03:2021 – Injection).
# * **Password Hashing:** Use a strong and adaptive password hashing algorithm like bcrypt or scrypt.  The example uses SHA256 with a salt for demonstration purposes only (OWASP Top 10: A02:2021 – Cryptographic Failures).
# * **API Key Rotation:** Implement a strategy for regularly rotating the Canvas API key. If an API key is compromised, it should be revoked and a new key should be generated. A process for regularly rotating API keys should be in place. This process should be automated and the old key immediately revoked upon generation of a new key (OWASP Top 10: A01:2021 – Broken Access Control, A05:2021 – Security Misconfiguration).
# * **Input Validation:**  Thoroughly validate all user inputs to prevent injection attacks (OWASP Top 10: A03:2021 – Injection).
# * **Error Handling:** Implement robust error handling and logging to detect and respond to security incidents (OWASP Top 10: A09:2021 – Security Logging and Monitoring Failures).
# * **Rate Limiting:**  Adjust rate limits based on the specific needs of the application (OWASP Top 10: A04:2021 – Design Vulnerabilities).
# * **Logging:**  Implement comprehensive logging for auditing and security monitoring (OWASP Top 10: A09:2021 – Security Logging and Monitoring Failures).
# * **Least Privilege:**  Run the application with the least privileges necessary (OWASP Top 10: A05:2021 – Security Misconfiguration).
# * **Dependencies:**  Use a `requirements.txt` file to manage dependencies and keep them up to date. Regularly audit dependencies for vulnerabilities (OWASP Top 10: A06:2021 – Vulnerable and Outdated Components).
# * **Security Audits and Penetration Testing:**  Conduct regular security audits and penetration testing to identify and address vulnerabilities (OWASP Top 10: A09:2021 – Security Logging and Monitoring Failures).
# * **CORS and CSRF:** Configure CORS and CSRF protection as needed (OWASP Top 10: A05:2021 – Security Misconfiguration, A01:2021 – Broken Access Control).
# * **Regular Updates:** Keep the Flask framework and all dependencies up to date with the latest security patches (OWASP Top 10: A06:2021 – Vulnerable and Outdated Components).

