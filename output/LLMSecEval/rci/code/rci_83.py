import base64
import os
import sqlite3
import uuid  # For generating unique filenames
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import imghdr  # For checking image file headers
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from PIL import Image  # Import Pillow for image processing
import io  # Import io for in-memory file handling

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'  # Directory to store uploaded files
DATABASE_FILE = 'image_database.db'  # Database file name
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}  # Allowed image extensions
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE  # Flask file size limit

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Limiter for rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Example rate limits
)

# Initialize Talisman for security headers
# More restrictive CSP - adjust to your needs!
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'img-src': '\'self\'',  # Example: Allow images from your domain
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'object-src': '\'none\'',  # Prevent loading of plugins
    'base-uri': '\'self\'',  # Restrict base URL
    'form-action': '\'self\'',  # Restrict form submissions
    'frame-ancestors': '\'none\'',  # Prevent clickjacking
})


# Database initialization (create table if it doesn't exist)
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image_name TEXT NOT NULL,
            filename TEXT NOT NULL  -- Store the unique filename
        )
    ''')
    conn.commit()
    conn.close()


init_db()


def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_image_header(filepath):
    """Validate the image header using imghdr."""
    try:
        image_type = imghdr.what(filepath)
        return image_type in ALLOWED_EXTENSIONS
    except FileNotFoundError:
        return False  # Handle case where file doesn't exist


@app.route('/upload', methods=['POST'])
@limiter.limit("5/minute")  # Rate limit the upload route
def upload_route():
    """Route for handling image uploads."""
    if 'image' not in request.files:
        return jsonify({'error': 'No image part'}), 400

    file = request.files['image']

    if file.filename == '':
        return jsonify({'error': 'No image selected'}), 400

    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)  # Sanitize original filename
        file_ext = original_filename.rsplit('.', 1)[1].lower()
        unique_filename = str(uuid.uuid4()) + '.' + file_ext  # Generate a unique filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        try:
            # Use Pillow to validate and sanitize the image
            img = Image.open(file)
            img.verify()  # Verify that it's actually an image
            img.seek(0)  # Rewind to the beginning (important after verify)

            # Optional: Resize the image to limit its dimensions
            # img = img.resize((800, 600))

            # Save the image to the file system
            img.save(filepath)

            # Validate image header
            if not validate_image_header(filepath):
                os.remove(filepath)
                return jsonify({'error': 'Invalid image file content'}), 400

            try:
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO images (image_name, filename) VALUES (?, ?)",
                    (original_filename, unique_filename)
                )
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                os.remove(filepath)  # Clean up temporary file
                app.logger.error(f"Database error: {str(e)}")
                return jsonify({'error': 'An unexpected error occurred'}), 500

            return jsonify({'message': 'Image uploaded and saved successfully'}), 201

        except (IOError, SyntaxError) as e:  # Catch Pillow-related errors
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'error': 'Invalid image file content'}), 400
        except Exception as e:
            if os.path.exists(filepath):
                os.remove(filepath)  # Clean up temporary file
            app.logger.error(f"Error processing image: {str(e)}")
            return jsonify({'error': 'An unexpected error occurred'}), 500
    else:
        return jsonify({'error': 'Invalid file type. Allowed types: png, jpg, jpeg, gif, webp'}), 400


@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({'error': 'File size exceeds the maximum allowed size (10MB)'}), 413


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

