import json
import secrets
import os
import uuid
from flask import Flask, request, abort, jsonify
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from logging.handlers import RotatingFileHandler
import mimetypes  # For content-based file validation
from jsonschema import validate, ValidationError
from PIL import Image  # For image validation

app = Flask(__name__)

# Configure logging
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler('app.log', maxBytes=1024 * 1024 * 10, backupCount=5)  # 10MB log files, keep 5 backups
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.INFO)  # Set logging level to INFO
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# Secret key for session management and other security features.
# Generate a strong, random key and store it securely (e.g., environment variable).
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    app.secret_key = secrets.token_hex(24)
    app.logger.warning("FLASK_SECRET_KEY not set in environment.  Generating a new one.  This is NOT recommended for production.")


# Define a safe directory for storing temporary files. Important for security.
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')  # Store uploads outside the app's root
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create directory if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Limit allowed file extensions

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"],  # Adjust limits as needed
    storage_uri=os.environ.get("RATELIMIT_STORAGE", "memory://")  # Use a persistent storage for production (e.g., redis://)
)

# CSP Header
CSP = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\'',  # Removed data:
    'font-src': '\'self\'',
    'object-src': '\'none\'',
    'base-uri': '\'none\'',
    'form-action': '\'self\'',
    'frame-ancestors': '\'none\'',
    'upgrade-insecure-requests': '1',
    # 'report-uri': '/csp_report'  # Implement a route to handle CSP reports - Removed for simplicity, implement if needed
}

def set_csp_header(response):
    """Sets the Content Security Policy header."""
    csp_value = '; '.join(f"{k} {v}" for k, v in CSP.items())
    response.headers['Content-Security-Policy'] = csp_value
    return response

app.after_request(set_csp_header)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Example schema for config validation
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "setting1": {"type": "string"},
        "setting2": {"type": "integer", "minimum": 1, "maximum": 100},  # Example value validation
        "setting3": {"type": "boolean"}
    },
    "required": ["setting1"]  # setting1 is a required field
}


def validate_config_values(config_data):
    """
    Performs value-based validation on the config data *after* schema validation.
    """
    if not isinstance(config_data, dict):
        raise ValueError("Config data must be a dictionary.")

    if "setting2" in config_data:
        if not 1 <= config_data["setting2"] <= 100:
            raise ValueError("setting2 must be between 1 and 100.")

    # Add more value-based validation rules here as needed.
    return True  # Return True if all validations pass


@app.route('/load_config', methods=['POST'])
@limiter.limit("10/minute")  # Limit requests to 10 per minute
def load_config():
    """
    Load the config from the request using JSON.
    """
    app.logger.info("Received /load_config request")
    try:
        config_data = request.get_json()  # Get JSON data from the request

        # Validate the config_data against the schema
        try:
            validate(instance=config_data, schema=CONFIG_SCHEMA)
        except ValidationError as e:
            app.logger.warning(f"Config validation error: {e.message}")
            return jsonify({"error": f"Invalid config format: {e.message}"}), 400

        # Validate the values in the config_data
        try:
            validate_config_values(config_data)
        except ValueError as e:
            app.logger.warning(f"Config value validation error: {e}")
            return jsonify({"error": f"Invalid config values: {e}"}), 400

        # Process the config data safely
        app.logger.info(f"Loaded config: {config_data}")
        return jsonify({"message": "Config loaded successfully"}), 200

    except json.JSONDecodeError:
        app.logger.warning("Invalid JSON format received")
        return jsonify({"error": "Invalid JSON format"}), 400
    except Exception as e:
        app.logger.exception("Error loading config")  # Log the full exception
        return jsonify({"error": "Error loading config"}), 500  # Generic error message


def validate_image_content(file_path):
    """Validates if the file is a valid image."""
    try:
        img = Image.open(file_path)
        img.verify()  # Verify that it is indeed an image
        # Optionally, you can perform further checks like image size, format, etc.
        return True
    except Exception:
        return False


def generate_unique_filename(filename):
    """Generates a unique filename using UUID."""
    ext = filename.rsplit('.', 1)[1].lower()
    unique_id = str(uuid.uuid4())
    return f"{unique_id}.{ext}"


@app.route('/upload', methods=['POST'])
@limiter.limit("5/minute")  # Limit file uploads to 5 per minute
def upload_file():
    """
    Secure file upload example.
    """
    app.logger.info("Received /upload request")
    if 'file' not in request.files:
        app.logger.warning("No file part in request")
        return jsonify({"error": 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        app.logger.warning("No selected file")
        return jsonify({"error": 'No selected file'}), 400

    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)  # Sanitize the original filename
        unique_filename = generate_unique_filename(original_filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        try:
            file.save(file_path)

            # Content-based validation
            file_mime_type = mimetypes.guess_type(file_path)[0]
            if file_mime_type and file_mime_type.startswith('image/'):
                if not validate_image_content(file_path):
                    os.remove(file_path)  # Remove invalid file
                    app.logger.warning("Invalid image content")
                    return jsonify({"error": "Invalid image content"}), 400
            else:
                # Add content validation for other file types here (e.g., PDF, TXT)
                app.logger.info(f"Uploaded file mime type: {file_mime_type}")
                pass # Implement content validation for other file types as needed

            app.logger.info(f"File uploaded successfully to {file_path}")
            return jsonify({"message": 'File uploaded successfully'}), 200

        except Exception as e:
            app.logger.exception(f"Error saving file: {e}")
            return jsonify({"error": "Error saving file"}), 500  # Generic error message
    else:
        app.logger.warning("Invalid file type")
        return jsonify({"error": 'Invalid file type'}), 400


@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps({
        "code": e.code,
        "error": e.name,  # Use a generic error name
    })
    response.content_type = "application/json"
    return response


if __name__ == '__main__':
    # Don't use debug=True in production!
    # Use a WSGI server like gunicorn or uWSGI instead.
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

