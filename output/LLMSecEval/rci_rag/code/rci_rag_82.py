import mysql.connector
import os
from PIL import Image  # For basic image validation
import io
import re  # Import the regular expression module
import uuid  # For generating unique filenames
import logging  # For proper logging

# Configure logging
logging.basicConfig(level=logging.ERROR,  # Or logging.INFO for less critical messages
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (sensitive information - handle securely in a real application)
DB_HOST = os.environ.get("DB_HOST", "localhost")  # Default to localhost if not set
DB_USER = os.environ.get("DB_USER", "image_uploader")  # Default to image_uploader if not set
DB_PASSWORD = os.environ.get("DB_PASSWORD", "secure_password")  # Use environment variable
DB_NAME = os.environ.get("DB_NAME", "image_database")  # Default to image_database if not set
# IMAGE_TABLE = "images"  # Hardcoded table name
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit
UPLOAD_DIRECTORY = "/path/to/allowed/upload/directory"  # Replace with your actual directory


def connect_to_database():
    """Connects to the MySQL database."""
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return connection
    except mysql.connector.Error as err:
        logging.error(f"Error connecting to database: {err}")
        return None


def is_allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_image(file_content):
    """Validates the image file content using PIL."""
    try:
        img = Image.open(io.BytesIO(file_content))
        img.verify()  # Verify that it's actually an image
        img.close()  # Close the image after verification
        return True
    except Exception as e:
        logging.error(f"Image validation failed: {e}")
        return False


def sanitize_filename(filename):
    """Sanitizes the filename to allow only alphanumeric characters, underscores, hyphens, periods, and spaces."""
    name, ext = os.path.splitext(filename)
    name = re.sub(r'[^a-zA-Z0-9_.\s-]', '', name)  # Allow spaces
    ext = re.sub(r'[^a-zA-Z0-9_.-]', '', ext)  # Remove invalid characters from the extension

    # Ensure the extension is valid *after* sanitization
    if ext and ext[1:].lower() not in ALLOWED_EXTENSIONS:
        return ""  # Or raise an exception, depending on your needs

    return name + ext


def store_image(filename, file_content):
    """Stores the image in the database using parameterized queries."""
    if not is_allowed_file(filename):
        logging.error("Invalid file extension.")
        return False

    if len(file_content) > MAX_FILE_SIZE:
        logging.error("File size exceeds the limit.")
        return False

    if not validate_image(file_content):
        logging.error("Image validation failed.")
        return False

    connection = connect_to_database()
    if not connection:
        return False

    try:
        cursor = connection.cursor()

        # Use parameterized query to prevent SQL injection
        query = "INSERT INTO images (filename, image_data) VALUES (%s, %s)"  # Hardcoded table name
        cursor.execute(query, (filename, file_content))
        connection.commit()
        logging.info(f"Image '{filename}' stored successfully.")
        return True

    except mysql.connector.Error as err:
        logging.exception("Error storing image:")  # Log the full exception details
        return False
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def handle_upload(file_path):
    """Handles the file upload process."""

    try:
        abs_file_path = os.path.abspath(file_path)
        if not abs_file_path.startswith(UPLOAD_DIRECTORY):
            logging.error("File path is outside of the allowed upload directory.")
            return False

        # Sanitize filename to prevent path traversal
        filename = os.path.basename(file_path)  # Extract filename, removing path
        filename = sanitize_filename(filename)  # Sanitize the filename

        if not filename:  # Check if the filename is empty after sanitization
            logging.error("Invalid filename. Filename contains only invalid characters or invalid extension.")
            return False

        # Check for path traversal after sanitization
        if any(sep in filename for sep in [os.path.sep, os.path.altsep] if sep):
            logging.error("Filename contains path separators after sanitization. Possible path traversal attempt.")
            return False

        # Generate a unique filename
        unique_filename = str(uuid.uuid4()) + "_" + filename

        with open(file_path, 'rb') as file:
            file_content = file.read()

        # Consider validating Content-Type here if integrating with a web application
        # content_type = magic.from_file(file_path, mime=True) # Requires libmagic
        # if content_type not in ['image/jpeg', 'image/png', 'image/gif']:
        #     print("Error: Invalid Content-Type.")
        #     return False

        return store_image(unique_filename, file_content)

    except FileNotFoundError:
        logging.error("Error: File not found.")
        return False
    except Exception as e:
        logging.exception("Error handling upload:")
        return False


if __name__ == "__main__":
    # Example usage:
    image_file_path = "example.jpg"  # Replace with the actual path to your image file

    # Create a dummy image file if it doesn't exist
    if not os.path.exists(image_file_path):
        with open(image_file_path, "wb") as f:
            f.write(b"Dummy image data")  # Replace with actual image data if needed

    if handle_upload(image_file_path):
        print("Upload successful.")
    else:
        print("Upload failed.")


# --- Database Setup (Run this once to create the database and table) ---
#  This part should be executed separately and securely, not as part of the main script.
#  Use a separate script with more privileged credentials to create the database and table.
#  Then, grant limited permissions to the 'image_uploader' user.

def create_database_and_table():
    """Creates the database and table (run once)."""
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=os.environ.get("DB_ROOT_USER", "root"),  # Use a privileged user for setup
            password=os.environ.get("DB_ROOT_PASSWORD", "root_password")  # Replace with the root password, get from env
        )
        cursor = connection.cursor()

        # Create the database
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        connection.database = DB_NAME  # Switch to the new database

        # Create the table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS images (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                image_data MEDIUMBLOB NOT NULL
            )
        """)

        # Create a dedicated user with limited privileges
        cursor.execute(f"CREATE USER IF NOT EXISTS '{DB_USER}'@'localhost' IDENTIFIED BY '{DB_PASSWORD}'")
        cursor.execute(f"GRANT SELECT, INSERT ON {DB_NAME}.images TO '{DB_USER}'@'localhost'")
        cursor.execute("FLUSH PRIVILEGES")  # Reload grant tables

        connection.commit()
        print("Database and table created successfully.")

    except mysql.connector.Error as err:
        print(f"Error creating database/table: {err}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# --- End of Database Setup ---

