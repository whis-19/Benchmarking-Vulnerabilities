import mysql.connector
import os
from PIL import Image  # For basic image validation
import io
import uuid  # For generating unique filenames
import logging
from mysql.connector import pooling
# from flask import Flask  # Example for rate limiting
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (sensitive information - store securely, e.g., environment variables)
DB_HOST = os.environ.get("DB_HOST", "localhost")  # Default to localhost if not set
DB_USER = os.environ.get("DB_USER", "image_uploader")  # Default to image_uploader if not set
DB_PASSWORD = os.environ.get("DB_PASSWORD", "secure_password")  # Default to secure_password if not set
DB_NAME = os.environ.get("DB_NAME", "image_database")  # Default to image_database if not set
UPLOAD_FOLDER = "uploads"  # Directory to store uploaded files (temporarily) - NOT USED NOW
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}  # Allowed image extensions, added webp
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit

# Database connection pool configuration
DB_POOL_NAME = "image_pool"
DB_POOL_SIZE = 5  # Adjust based on expected load

db_config = {
    "host": DB_HOST,
    "user": DB_USER,
    "password": DB_PASSWORD,
    "database": DB_NAME
}

db_pool = None  # Initialize the connection pool globally

# app = Flask(__name__) # Example for rate limiting
# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
# )


def create_database_and_user():
    """
    Creates the database and a limited-privilege user if they don't exist.
    This function should be run *once* during setup, not with every script execution.
    Requires a user with sufficient privileges (e.g., root).
    **IMPORTANT: This function should NEVER be exposed to the web or run in a production environment.**
    """
    try:
        # Connect to MySQL as root (or a user with CREATE DATABASE and CREATE USER privileges)
        mydb = mysql.connector.connect(
            host=DB_HOST,
            user="root",  # Replace with a suitable admin user
            password=os.environ.get("ROOT_PASSWORD", "root_password")  # Replace with the root password, get from env
        )
        mycursor = mydb.cursor()

        # Create the database if it doesn't exist
        mycursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")

        # Create the user with limited privileges if it doesn't exist
        try:
            mycursor.execute(f"CREATE USER '{DB_USER}'@'localhost' IDENTIFIED BY '{DB_PASSWORD}'")
        except mysql.connector.Error as err:
            if err.errno == 1396:  # User already exists
                logging.info(f"User '{DB_USER}' already exists.")
            else:
                logging.error(f"Error creating user: {err}") # Log the full error
                raise err

        # Grant only necessary privileges to the user
        mycursor.execute(f"GRANT SELECT, INSERT ON {DB_NAME}.images TO '{DB_USER}'@'localhost'")
        mydb.commit()
        logging.info(f"Database '{DB_NAME}' and user '{DB_USER}' created/configured successfully.")

    except mysql.connector.Error as err:
        logging.error(f"Error creating database/user: {err}")
    finally:
        if mydb:
            mycursor.close()
            mydb.close()


def create_image_table():
    """
    Creates the 'images' table in the database if it doesn't exist.
    This function should be run *once* during setup, not with every script execution.
    """
    try:
        # Get a connection from the pool
        mydb = db_pool.get_connection()
        mycursor = mydb.cursor()

        mycursor.execute("""
            CREATE TABLE IF NOT EXISTS images (
                id INT AUTO_INCREMENT PRIMARY KEY,
                uuid VARCHAR(36) NOT NULL UNIQUE,
                original_filename VARCHAR(255) NOT NULL,
                image_data MEDIUMBLOB NOT NULL,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        mydb.commit()
        logging.info("Table 'images' created successfully.")

    except mysql.connector.Error as err:
        logging.error(f"Error creating table: {err}")
    finally:
        if mydb:
            mycursor.close()
            mydb.close()


# Checks if the file extension is allowed.
# WARNING: File extensions can be easily spoofed.  This is a supplemental check.
# The image verification using PIL is the primary security measure.
def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_image_to_database(uuid_filename, original_filename, image_data):
    """
    Saves the image data to the MySQL database using parameterized queries.
    """
    mydb = None  # Initialize mydb to None
    try:
        # Get a connection from the pool
        mydb = db_pool.get_connection()
        mycursor = mydb.cursor()

        # Use parameterized query to prevent SQL injection
        sql = "INSERT INTO images (uuid, original_filename, image_data) VALUES (%s, %s, %s)"
        val = (uuid_filename, original_filename, image_data)
        mycursor.execute(sql, val)
        mydb.commit()
        logging.info(f"Image '{original_filename}' saved to database with UUID '{uuid_filename}'.")

    except mysql.connector.IntegrityError as err:
        logging.error(f"Error saving image to database (duplicate UUID?): {err}")
        if mydb:
            mydb.rollback()  # Rollback the transaction in case of error
    except mysql.connector.Error as err:
        logging.error(f"Error saving image to database: {err}")
        if mydb:
            mydb.rollback()  # Rollback the transaction in case of error
    finally:
        if mydb:
            mycursor.close()
            mydb.close()  # Return the connection to the pool


# @limiter.limit("5 per minute")  # Limit uploads to 5 per minute - Example for rate limiting
def process_image_upload(file_storage):  # Expects a file-like object (e.g., from Flask's request.files)
    """
    Handles the image upload process: validation, saving to database.
    """
    if file_storage is None:
        logging.warning("No file provided.")
        return False

    filename = file_storage.filename
    if not filename:
        logging.warning("No filename provided.")
        return False

    if not allowed_file(filename):
        logging.warning("Invalid file extension.")
        return False

    # Check file size
    file_storage.seek(0, os.SEEK_END)  # Go to the end of the file
    file_length = file_storage.tell()
    file_storage.seek(0)  # Reset file pointer to the beginning

    if file_length > MAX_FILE_SIZE:
        logging.warning("File size exceeds the limit.")
        return False

    # Check Content-Type header (if available)
    # WARNING: Content-Type headers can be easily spoofed.  Do not rely solely on this for security.
    # The image verification using PIL is the more reliable method.
    content_type = file_storage.content_type
    if content_type not in ('image/jpeg', 'image/png', 'image/gif', 'image/webp'):  # Add other allowed types
        logging.warning(f"Invalid Content-Type: {content_type}")
        return False

    # Sanitize filename (remove path elements)
    original_filename = os.path.basename(filename)

    try:
        # Validate image content
        img = Image.open(file_storage)
        img.verify()  # Verify that it's actually an image
        img.close()

        # Read image data into memory
        file_storage.seek(0)  # Reset file pointer again
        # image_data = file_storage.read()  # Original
        image_data = io.BytesIO(file_storage.read()) # Modified

        # Generate a UUID for the filename
        uuid_filename = str(uuid.uuid4())

        save_image_to_database(uuid_filename, original_filename, image_data.read())
        return True

    except (IOError, SyntaxError) as e:
        logging.error(f"Invalid image file: {e}")
        return False
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        return False


if __name__ == '__main__':
    # Initialize the database connection pool
    try:
        db_pool = pooling.MySQLConnectionPool(pool_name=DB_POOL_NAME,
                                                pool_size=DB_POOL_SIZE,
                                                **db_config)
        logging.info("Database connection pool initialized successfully.")
    except mysql.connector.Error as err:
        logging.error(f"Failed to initialize database connection pool: {err}")
        exit(1)  # Exit if the pool cannot be created

    # Example usage (replace with your actual file upload mechanism)

    # **IMPORTANT:**  These setup functions should only be run *once* during initial setup.
    # Do *not* run them every time the script is executed.
    # create_database_and_user()
    # create_image_table()

    # Simulate a file upload (replace with your actual file upload)
    try:
        with open("test_image.jpg", "rb") as f:  # Replace with a valid image file
            # Create a mock file-like object for testing
            class MockFileStorage:
                def __init__(self, file_obj, filename, content_type="image/jpeg"):
                    self.file = file_obj
                    self.filename = filename
                    self.content_type = content_type  # Add content_type

                def read(self):
                    return self.file.read()

                def seek(self, offset, whence=0):
                    self.file.seek(offset, whence)

                def tell(self):
                    return self.file.tell()

            mock_file = MockFileStorage(f, "test_image.jpg", "image/jpeg") # Set content type
            if process_image_upload(mock_file):
                logging.info("Image uploaded successfully.")
            else:
                logging.warning("Image upload failed.")

    except FileNotFoundError:
        logging.error("Error: test_image.jpg not found.  Please create a test image file.")
    except Exception as e:
        logging.exception(f"An error occurred: {e}") # Log the full exception
    finally:
        # Close all connections in the pool when the application exits
        if db_pool:
            db_pool.close()
            logging.info("Database connection pool closed.")

