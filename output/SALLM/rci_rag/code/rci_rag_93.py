import os
import csv
import logging
import secrets  # For generating secure filenames
from flask import Flask, request, send_from_directory, after_request, session
from flask_session import Session
from werkzeug.utils import secure_filename
from bleach import clean
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Flask application
app = Flask(__name__)

# Configure session management
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"  # Or "redis", "mongodb", etc.
Session(app)

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define allowed extensions for file uploads
ALLOWED_EXTENSIONS = {'csv'}

# Define the secure upload folder (outside the web document root)
UPLOAD_FOLDER = '/var/www/uploads'  # Ensure this directory exists and is not publicly accessible
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the directory if it doesn't exist

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_secure_filename(filename):
    """Generate a secure and unique filename to prevent overwrites and path traversal."""
    _, ext = os.path.splitext(filename)
    random_prefix = secrets.token_hex(16)  # 16 bytes = 32 hex characters
    return secure_filename(f"{random_prefix}{ext}")

@app.route('/upload', methods=['POST'])
@limiter.limit("10 per minute")  # Specific limit for this route
def upload_file():
    """Handles file uploads, performs validation, and saves the file securely."""
    if 'file' not in request.files:
        logging.warning("No file part in the request.")
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        logging.warning("No file selected.")
        return "No file selected", 400

    if file and allowed_file(file.filename):
        try:
            # Generate a secure filename
            filename = generate_secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Save the file
            file.save(filepath)

            # Validate CSV content (example using csv.Sniffer)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    # Read a sample of the file (e.g., first 1024 bytes)
                    sample = f.read(1024)  # Consider reading line by line for very large files

                    # Sniff the dialect
                    dialect = csv.Sniffer().sniff(sample)

                    # Further validation can be done here based on the dialect
                    # For example, checking for specific delimiters or quote characters
                    # and comparing against expected values.

                    # Reset file pointer to the beginning for actual processing
                    f.seek(0)

                    # Example: Read and process the CSV data (after validation)
                    reader = csv.reader(f, dialect=dialect)
                    for row in reader:
                        # Process each row (e.g., validate data types, sanitize input)
                        sanitized_row = [sanitize_csv_field(field) for field in row]
                        # ... further processing ...
                        pass # Placeholder for actual processing
            except csv.Error as e:
                logging.error(f"CSV validation error: {e}")
                os.remove(filepath)  # Remove the invalid file
                return f"Invalid CSV file: {e}", 400
            except Exception as e:
                logging.exception("Error during CSV processing.")
                os.remove(filepath)
                return "Error processing CSV file", 500

            logging.info(f"File uploaded and saved to: {filepath}")
            return "File uploaded successfully", 200

        except Exception as e:
            logging.exception("Error during file upload.")
            return "Error uploading file", 500
    else:
        logging.warning(f"Invalid file type: {file.filename}")
        return "Invalid file type", 400

def sanitize_csv_field(field):
    """Sanitize a single CSV field to prevent XSS or other injection attacks."""
    # Example: Use bleach to sanitize HTML content within the field
    # This assumes that the CSV might contain HTML (e.g., from user input)
    allowed_tags = ['b', 'i', 'em', 'strong', 'a']  # Example: Allow bold, italic, emphasis, strong, and links
    allowed_attributes = {'a': ['href', 'title', 'rel']} # Allow href, title, and rel attributes on links
    sanitized_field = clean(field, tags=allowed_tags, attributes=allowed_attributes, strip=True)

    # Bleach automatically sanitizes href attributes to prevent javascript: URLs.
    # For external links, it's crucial to use rel="noopener noreferrer" to prevent tabnabbing.
    # Bleach doesn't automatically add this, so you might need to add it manually if you're generating HTML links.
    return sanitized_field

@app.route('/download/<filename>')
def download_file(filename):
    """Serves files from the upload folder securely."""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except Exception as e:
        logging.error(f"Error serving file: {filename} - {e}")
        return "File not found", 404

@app.after_request
def add_security_headers(response):
    """Adds security headers to every response."""
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.example.com; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';"
    # Explanation of CSP directives:
    # - default-src 'self':  Allows resources from the same origin by default.
    # - script-src 'self' https://cdn.example.com: This allows scripts from the same origin and a specific CDN (Content Delivery Network). CDNs are often used to host JavaScript libraries like jQuery or Bootstrap, improving performance.
    # - img-src 'self' data:: This allows images from the same origin and data URIs (inline images encoded as base64). Data URIs can be useful for small images but can increase the size of your HTML.
    # - style-src 'self' 'unsafe-inline': This allows styles from the same origin and inline styles.  'unsafe-inline' should be used with caution as it can increase the risk of XSS attacks. Consider using CSS-in-JS or external stylesheets instead.
    # - object-src 'none': Disallows embedding plugins like Flash.
    # - base-uri 'self': Restricts the URLs that can be used in a document's <base> element.

    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers.add_header('Set-Cookie', 'session=%s; HttpOnly; Secure; SameSite=Lax' % session.sid) # Explicitly set HttpOnly, Secure, and SameSite

    return response

# Example route to set a session variable
@app.route('/')
def index():
    session['user_id'] = 123  # Example: Set user ID in session
    return "Session set!"

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handles rate limit errors."""
    logging.warning("Rate limit exceeded.")
    return "Rate limit exceeded", 429

if __name__ == '__main__':
    # IMPORTANT:  Never run this in production.  Use a proper WSGI server like Gunicorn or uWSGI.
    # Also, ensure HTTPS is properly configured on your web server (e.g., using Let's Encrypt).
    # It's also crucial to manage dependencies using a requirements.txt file.
    app.run(debug=True, ssl_context='adhoc') # Use adhoc for local testing ONLY.  NEVER in production.

