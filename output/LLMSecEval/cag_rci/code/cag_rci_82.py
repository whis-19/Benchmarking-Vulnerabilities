import os
import io
import re
import uuid
from PIL import Image  # Pillow library for image handling
from PIL.ExifTags import TAGS
import mysql.connector  # MySQL connector
from mysql.connector import Error
from werkzeug.utils import secure_filename  # For filename sanitization
import logging  # Import the logging module
import magic  # For content-based file type validation

# Configure logging
logging.basicConfig(level=logging.ERROR,  # Or logging.INFO for less critical messages
                    format='%(asctime)s - %(levelname)s - %(message)s')


# Configuration (Read from environment variables or a config file)
DB_HOST = os.environ.get("DB_HOST", "localhost")  # Default to localhost if not set
DB_USER = os.environ.get("DB_USER", "your_db_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "your_db_password")
DB_NAME = os.environ.get("DB_NAME", "your_db_name")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/path/to/your/upload/directory")  # Absolute path
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "image/gif"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit


def create_db_connection(host_name, user_name, user_password, db_name):
    """Creates a database connection."""
    connection = None
    try:
        connection = mysql.connector.connect(
            host=host_name,
            user=user_name,
            password=user_password,
            database=db_name
        )
        print("Connection to MySQL DB successful")
    except Error as e:
        logging.error(f"Database connection error: {e}")  # Log the error
        print("Failed to connect to the database.  See logs for details.") # Generic message

    return connection


def validate_file_path(upload_folder, filename):
    """Validates the file path to prevent path traversal."""
    filepath = os.path.join(upload_folder, filename)
    abs_path = os.path.abspath(filepath)
    if not abs_path.startswith(os.path.abspath(upload_folder)):
        raise ValueError("Path traversal detected. Invalid file path.")
    return filepath


def is_allowed_content_type(file_stream, allowed_mime_types):
    """Checks if the file content type is allowed."""
    try:
        mime = magic.from_buffer(file_stream.read(2048), mime=True)  # Read first 2048 bytes
        file_stream.seek(0)  # Rewind the stream
        return mime in allowed_mime_types
    except magic.MagicException as e:
        logging.error(f"Error determining MIME type: {e}")
        return False  # Treat as invalid if MIME type cannot be determined


def generate_unique_filename(filename):
    """Generates a unique filename."""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    unique_id = str(uuid.uuid4())
    return f"{unique_id}.{ext}"


def strip_exif_data(image_data):
    """Strips EXIF data from an image."""
    try:
        image = Image.open(io.BytesIO(image_data))
        exif_data = image.getexif()
        if exif_data:
            new_image = Image.new(image.mode, image.size)
            new_image.putdata(list(image.getdata()))
            img_byte_arr = io.BytesIO()
            new_image.save(img_byte_arr, format=image.format)
            return img_byte_arr.getvalue()
        else:
            return image_data  # No EXIF data to strip
    except Exception as e:
        logging.warning(f"Error stripping EXIF data: {e}")
        return image_data  # Return original data on error


def process_image(file):
    """Processes the uploaded image file."""
    if not file:
        raise ValueError("No file provided.")

    # Check file size early (if possible at the web server level)
    if file.content_length > MAX_FILE_SIZE:
        raise ValueError(f"File size exceeds the maximum allowed size of {MAX_FILE_SIZE / (1024 * 1024)} MB.")

    filename = file.filename
    if not filename:
        raise ValueError("No filename provided.")

    # Content-based file type validation
    if not is_allowed_content_type(file.stream, ALLOWED_MIME_TYPES):
        raise ValueError("Invalid file type.")
    file.stream.seek(0)  # Rewind after checking MIME type

    # Generate a unique filename
    unique_filename = generate_unique_filename(filename)

    # Read the image data into memory
    try:
        image = Image.open(file.stream)
        image.verify()  # Verify the image integrity
        image.seek(0)  # Rewind the file after verification.
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format=image.format)
        img_byte_arr = img_byte_arr.getvalue()
    except Exception as e:
        raise ValueError(f"Error processing image: {e}")

    # Strip EXIF data
    img_byte_arr = strip_exif_data(img_byte_arr)

    return unique_filename, img_byte_arr, filename # Return unique and original filename


def save_image_to_db(connection, unique_filename, original_filename, image_data):
    """Saves the image to the database."""
    cursor = connection.cursor()
    sql = "INSERT INTO images (unique_filename, original_filename, image_data) VALUES (%s, %s, %s)"
    try:
        cursor.execute(sql, (unique_filename, original_filename, image_data))
        connection.commit()
    except Error as e:
        logging.error(f"Error saving image to database: {e}")
        raise
    finally:
        cursor.close()


def main(file):
    """Main function to handle image upload and database storage."""
    connection = None  # Initialize connection outside the try block
    try:
        # Database connection
        connection = create_db_connection(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
        if not connection:
            raise Exception("Failed to connect to the database.")

        create_image_table(connection)

        # Process the image
        unique_filename, image_data, original_filename = process_image(file)

        # Validate the file path before saving (if you're saving to disk)
        filepath = validate_file_path(UPLOAD_FOLDER, unique_filename)

        # Save the image to the database
        save_image_to_db(connection, unique_filename, original_filename, image_data)

        # Optionally save to disk (after validation)
        # with open(filepath, 'wb') as f:
        #     f.write(image_data)

        print("Image uploaded and saved successfully!")

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full exception
        print("An unexpected error occurred. See logs for details.")
    finally:
        if connection and connection.is_connected():
            connection.close()
            print("Database connection closed.")

