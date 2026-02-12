import mysql.connector
import os
from PIL import Image  # Pillow library for image handling
import io
import hashlib  # For hashing filenames
import logging  # For logging
import mimetypes  # For MIME type detection
import magic  # For more robust MIME type detection
import secrets  # For generating secure random values

# Configure logging
logging.basicConfig(filename='image_upload.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration (IMPORTANT: Store these securely, e.g., environment variables)
DB_HOST = "localhost"
DB_USER = os.environ.get("DB_USER")  # Get from environment variable
DB_PASSWORD = os.environ.get("DB_PASSWORD")  # Get from environment variable
DB_NAME = "your_db_name"
TABLE_NAME = "images"  # Table to store image data

# Security Considerations:
# 1.  Input Validation:  Sanitize and validate the filename and file content.
# 2.  File Size Limit:  Prevent excessively large files from being uploaded.
# 3.  File Type Validation:  Restrict allowed file types to prevent malicious uploads.
# 4.  Database Credentials:  Never hardcode credentials directly in the script. Use environment variables or a secure configuration file.
# 5.  Error Handling:  Implement robust error handling to prevent information leakage.
# 6.  Prepared Statements:  Use prepared statements to prevent SQL injection vulnerabilities.
# 7.  Hashing:  Hash filenames to prevent directory traversal attacks and predictable filenames.
# 8.  Permissions:  Ensure the database user has only the necessary permissions.
# 9.  Logging:  Log important events for auditing and debugging.
# 10. Secure Connection: Use SSL/TLS for database connections, especially over a network.

# Constants for security
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif"}  # Allowed image extensions
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/gif"}  # Allowed MIME types
BASE_UPLOAD_DIR = "/path/to/your/allowed/upload/directory"  # Replace with your actual directory
ALLOWED_TABLE_NAMES = {"images"}  # Whitelist table names


def is_allowed_file(filename, file_content):
    """Checks if the file extension and MIME type are allowed."""
    # Prioritize content-based checks. Remove extension check if possible.
    # if not any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
    #     return False

    # mime_type, _ = mimetypes.guess_type(filename)
    # if mime_type not in ALLOWED_MIME_TYPES:
    #     return False

    # Double check using file content (more reliable)
    try:
        mime_type_from_content = magic.from_buffer(file_content, mime=True).decode('utf-8')
        if mime_type_from_content not in ALLOWED_MIME_TYPES:
            return False
    except Exception as e:
        logging.error(f"Error determining MIME type from content: {e}")
        return False

    return True


def generate_hashed_filename(filename):
    """Generates a unique, hashed filename."""
    # Use a combination of the original filename, current timestamp, and a random salt
    # to create a more robust hash.
    salt = secrets.token_hex(16)  # Generate a random salt
    # Sanitize filename before hashing
    safe_filename = "".join(c for c in filename if c.isalnum() or c in ['.', '_', '-'])
    combined_string = f"{safe_filename}{time.time()}{salt}"
    hashed_filename = hashlib.sha256(combined_string.encode()).hexdigest()
    return hashed_filename


def store_image_in_db(image_path):
    """Stores the image in the MySQL database."""

    # Input validation for image_path
    abs_path = os.path.abspath(image_path)
    if not abs_path.startswith(BASE_UPLOAD_DIR):
        logging.error(f"Invalid image path: {image_path}")
        print("Error: Image storage failed.")  # Generic error for user
        return False

    if not os.path.isfile(image_path):
        logging.error(f"File not found: {image_path}")
        print("Error: Image storage failed.")  # Generic error for user
        return False

    file_size = os.path.getsize(image_path)
    if file_size > MAX_FILE_SIZE:
        logging.error(f"File size exceeds the maximum allowed size ({MAX_FILE_SIZE} bytes).")
        print("Error: Image storage failed.")  # Generic error for user
        return False

    filename = os.path.basename(image_path)

    try:
        with open(image_path, "rb") as image_file:
            image_data = image_file.read()

        if not is_allowed_file(filename, image_data):
            logging.error(f"Invalid file type. Allowed extensions: {ALLOWED_EXTENSIONS}, Allowed MIME types: {ALLOWED_MIME_TYPES}")
            print("Error: Image storage failed.")  # Generic error for user
            return False

        # Validate image data using Pillow
        try:
            img = Image.open(io.BytesIO(image_data))
            img.verify()  # Verify that it's a valid image
            img.close()
        except Exception as e:
            logging.error(f"Invalid image data: {e}")
            print("Error: Image storage failed.")  # Generic error for user
            return False

        # Generate a secure, hashed filename
        hashed_filename = generate_hashed_filename(filename)
        # Do NOT preserve the original extension
        # file_extension = os.path.splitext(filename)[1]
        # safe_filename = hashed_filename + file_extension  # Keep the extension
        safe_filename = hashed_filename

        # Connect to the database
        try:
            mydb = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                use_pure=True,  # Optional: Use pure Python implementation (safer)
                ssl_ca='/path/to/your/mysql/ca.pem',  # Enable SSL and specify the CA certificate
                ssl_disabled=False  # Disable SSL if not configured.  Enable if possible.
            )

            mycursor = mydb.cursor()

            # Table name validation
            if TABLE_NAME not in ALLOWED_TABLE_NAMES:
                logging.error(f"Invalid table name: {TABLE_NAME}")
                print("Error: Image storage failed.")
                return False

            # Use a prepared statement to prevent SQL injection
            sql = "INSERT INTO `{}` (filename, image_data) VALUES (%s, %s)".format(TABLE_NAME)  # Safer now that TABLE_NAME is validated
            val = (safe_filename, image_data)  # Store the hashed filename
            mycursor.execute(sql, val)

            mydb.commit()

            logging.info(f"Image '{filename}' stored successfully with hashed filename '{safe_filename}'.")
            print("Image stored successfully.")  # User-friendly message

            return True

        except mysql.connector.Error as err:
            logging.error(f"Database error: {err}")
            print("Error: Image storage failed.")  # Generic error for user
            return False
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
            print("Error: Image storage failed.")  # Generic error for user
            return False
        finally:
            if 'mydb' in locals() and mydb.is_connected():
                mycursor.close()
                mydb.close()

    except FileNotFoundError:
        logging.error(f"File not found: {image_path}")
        print("Error: Image storage failed.")
        return False
    except IOError as e:
        logging.error(f"IOError: {e}")
        print("Error: Image storage failed.")
        return False
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        print("Error: Image storage failed.")  # Generic error for user
        return False


if __name__ == "__main__":
    # Example usage:
    image_file_path = "path/to/your/image.jpg"  # Replace with the actual path to your image file
    if store_image_in_db(image_file_path):
        print("Image stored successfully.")
    else:
        print("Image storage failed.")

