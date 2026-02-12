import boto3  # pip install boto3
import os
import uuid
import re
from slugify import slugify  # pip install python-slugify
from PIL import Image
import io
import logging
import magic  # pip install python-magic
import json
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
from flask_talisman import Talisman

# Configuration (Externalize these!)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
MAX_IMAGE_DIMENSION = 2048
MAX_UPLOAD_RATE = 10  # Maximum uploads per minute
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
S3_BUCKET = os.environ.get("S3_BUCKET")
S3_REGION = os.environ.get("S3_REGION")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
CSP_POLICY = {
    'default-src': '\'self\'',
    'img-src': '*',  # Adjust as needed
    'script-src': '\'self\'',
    'style-src': '\'self\''
}

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask
app = Flask(__name__)

# Initialize Redis connection
redis_connection = redis.from_url(REDIS_URL)

# Configure Flask-Limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,  # Use IP address for rate limiting
    storage_uri=REDIS_URL,  # Use Redis for storage
    strategy="fixed_window"  # Fixed window strategy
)

# Configure Talisman (Security Headers)
talisman = Talisman(
    app,
    content_security_policy=CSP_POLICY,
    content_security_policy_nonce_in=['script-src'],
    force_https=True,  # Enforce HTTPS
    frame_options='SAMEORIGIN',
    x_content_type_options='nosniff',
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,  # 1 year
    strict_transport_security_include_subdomains=True,
    referrer_policy='no-referrer'
)

# Initialize S3 client
s3 = boto3.client(
    's3',
    region_name=S3_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

# Initialize python-magic
try:
    mime = magic.Magic(mime=True)
except magic.MagicException as e:
    logging.error(f"Failed to initialize python-magic: {e}")
    mime = None  # Disable content-based type checking if magic is not available

def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """Sanitizes the filename more robustly."""
    name, ext = os.path.splitext(filename)

    # Use slugify to handle Unicode and remove potentially dangerous characters
    name = slugify(name, allow_unicode=True)  # Keep Unicode characters if needed

    ext = '.' + ext.lstrip('.')  # Ensure extension starts with a dot
    if ext and ext.lower() not in ['.' + e for e in ALLOWED_EXTENSIONS]:
        return None  # Invalid extension after sanitization

    # Double-check extension after sanitization
    if not ext or not allowed_file(name + ext):  # Check if the extension is still valid
        return None

    return name + ext

def validate_image_content(file_content):
    """Validates image content using Pillow and python-magic."""
    try:
        img = Image.open(io.BytesIO(file_content))
        img.verify()  # Verify that it is actually an image
        img.seek(0)  # Rewind the file after verify
        width, height = img.size
        if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
            return False, "Image dimensions exceed maximum allowed size."

        # Content-based type checking using python-magic
        if mime:
            file_type = mime.from_buffer(file_content)
            if not file_type.startswith('image/'):
                logging.warning(f"Content-Type mismatch: Expected image, got {file_type}")
                return False, "Content-Type mismatch: File does not appear to be an image."

        return True, None
    except Exception as e:
        logging.error(f"Image validation failed: {e}")
        return False, "Invalid image format or corrupted file."

def upload_image_to_s3(file_content, filename):
    """Uploads the image to S3."""
    try:
        s3.upload_fileobj(
            io.BytesIO(file_content),
            S3_BUCKET,
            filename,
            ExtraArgs={'ACL': 'public-read', 'ContentType': 'image/jpeg'}  # Adjust ContentType
        )
        return f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{filename}"  # Public URL
    except Exception as e:
        logging.error(f"S3 upload failed: {e}")
        return None

def upload_image(file, ip_address):
    """
    Handles the image upload process.

    Args:
        file: The uploaded file object (e.g., from Flask's request.files).
        ip_address: The IP address of the client making the request.

    Returns:
        A tuple: (success, message, filename (if successful))
    """

    if not file:
        log_data = {"ip_address": ip_address, "filename": None, "error": "No file uploaded"}
        logger.warning(json.dumps(log_data))
        return False, "No file uploaded.", None

    filename = file.filename
    sanitized_filename = sanitize_filename(filename)

    if not sanitized_filename:
        log_data = {"ip_address": ip_address, "filename": filename, "error": "Invalid file extension or filename"}
        logger.warning(json.dumps(log_data))
        return False, "Invalid file extension or filename.", None

    if not allowed_file(sanitized_filename):
        log_data = {"ip_address": ip_address, "filename": sanitized_filename, "error": "Invalid file extension"}
        logger.warning(json.dumps(log_data))
        return False, "Invalid file extension. Allowed extensions: {}".format(ALLOWED_EXTENSIONS), None

    # Rate limiting (handled by Flask-Limiter)

    try:
        file_content = file.read()
    except Exception as e:
        log_data = {"ip_address": ip_address, "filename": sanitized_filename, "error": f"Error reading file: {e}"}
        logger.error(json.dumps(log_data))
        return False, "Error reading file.", None

    # Check file size
    if len(file_content) > MAX_FILE_SIZE:
        log_data = {"ip_address": ip_address, "filename": sanitized_filename, "error": "File size exceeds the maximum allowed size"}
        logger.warning(json.dumps(log_data))
        return False, "File size exceeds the maximum allowed size ({}MB).".format(MAX_FILE_SIZE / (1024 * 1024)), None

    # Validate image content
    is_valid, validation_message = validate_image_content(file_content)
    if not is_valid:
        log_data = {"ip_address": ip_address, "filename": sanitized_filename, "error": validation_message}
        logger.warning(json.dumps(log_data))
        return False, validation_message, None

    # Upload to S3 instead of local storage
    file_ext = os.path.splitext(sanitized_filename)[1].lower()
    s3_filename = f"{uuid.uuid4()}_{os.path.splitext(sanitized_filename)[0]}{file_ext}"  # Add original name as suffix
    s3_url = upload_image_to_s3(file_content, s3_filename)

    if not s3_url:
        log_data = {"ip_address": ip_address, "filename": sanitized_filename, "error": "File upload to S3 failed"}
        logger.error(json.dumps(log_data))
        return False, "File upload to S3 failed.", None

    log_data = {"ip_address": ip_address, "filename": sanitized_filename, "status": "success", "s3_url": s3_url}
    logger.info(json.dumps(log_data))
    return True, "Image uploaded successfully.", s3_url  # Return the S3 URL

@app.route('/upload', methods=['POST'])
@limiter.limit(f"{MAX_UPLOAD_RATE}/minute")  # Apply rate limit
def upload_route():
    if request.method != 'POST':
        return jsonify({'success': False, 'message': 'Method not allowed'}), 405

    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400

    ip_address = request.remote_addr  # Get the client's IP address

    success, message, filename = upload_image(file, ip_address)

    if success:
        return jsonify({'success': True, 'message': message, 'url': filename}), 200  # Return URL
    else:
        return jsonify({'success': False, 'message': message}), 400

if __name__ == '__main__':
    # Ensure the upload directory exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=False)  # NEVER USE debug=True IN PRODUCTION!

