import base64
import sqlite3
import os
import uuid  # For generating unique filenames
from PIL import Image  # For image validation
from io import BytesIO
from passlib.hash import bcrypt  # For password hashing
import logging  # For logging
import imghdr  # For more robust image type detection

# Configuration (adjust as needed)
DATABASE_PATH = "image_database.db"
ALLOWED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/gif"]  # MIME types
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5MB limit
UPLOAD_FOLDER = "uploads"  # Store uploaded files temporarily (before processing)

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def create_database():
    """Creates the database and table if they don't exist.  Sets up minimal permissions."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Create the images table.  Use a separate table for user permissions if needed.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                image_name TEXT NOT NULL,  -- Store the unique filename
                base64_data TEXT,  -- Store base64 data only if not using a file storage service
                image_url TEXT, -- Store the URL if using a file storage service
                user_id INTEGER NOT NULL,  -- Link to a user (for access control)
                upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create a users table (example for user management and permissions)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                -- Store password hashes, NOT plain text passwords!
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user'  -- e.g., 'user', 'admin'
            )
        """)

        conn.commit()

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        if conn:
            conn.rollback()  # Rollback in case of error
    finally:
        if conn:
            conn.close()


def validate_image(file_path):
    """Validates the image file based on content and metadata."""
    try:
        img = Image.open(file_path)

        # More robust image processing to detect malicious content
        img = img.resize((100, 100))  # Resize the image
        img = img.convert("RGB")  # Convert to RGB format
        img.save(file_path + ".processed.tmp", "JPEG") # Save a processed version
        img.close()

        # Use imghdr for more reliable image type detection
        image_type = imghdr.what(file_path + ".processed.tmp")

        os.remove(file_path + ".processed.tmp") # Clean up the processed file

        if image_type == 'jpeg':
            return "image/jpeg"
        elif image_type == 'png':
            return "image/png"
        elif image_type == 'gif':
            return "image/gif"
        else:
            return None  # Unknown or invalid format

    except Exception as e:
        logging.error(f"Image validation error: {e}")
        return None


def upload_image(image_file, user_id):
    """
    Uploads an image, converts it to base64 (or stores in a file service), and stores metadata in the database.

    Args:
        image_file:  The uploaded file object (e.g., from Flask's request.files).
        user_id: The ID of the user uploading the image.  Crucial for access control.

    Returns:
        True if the upload was successful, False otherwise.
    """
    if not image_file:
        logging.warning("No image file provided.")
        return False

    # 1. File Size Check (before saving to disk)
    image_file.seek(0, os.SEEK_END)  # Go to the end of the file
    file_length = image_file.tell()
    image_file.seek(0)  # Reset the file pointer to the beginning

    if file_length > MAX_FILE_SIZE_BYTES:
        logging.warning("File size exceeds the maximum allowed size.")
        return False

    # 2. Save the file temporarily to disk for validation (safer than in-memory validation)
    filename = image_file.filename
    # Completely ignore user-provided extension
    unique_filename = str(uuid.uuid4())  # Create a unique name (without extension initially)
    temp_file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    try:
        image_file.save(temp_file_path)
    except Exception as e:
        logging.error(f"Error saving file to disk: {e}")
        return False

    # 3. Validate Image Content and Metadata
    mime_type = validate_image(temp_file_path)
    if mime_type not in ALLOWED_IMAGE_TYPES:
        logging.warning(f"Invalid image type: {mime_type}. Allowed types: {ALLOWED_IMAGE_TYPES}")
        os.remove(temp_file_path)  # Remove the invalid file
        return False

    # Determine file extension based on MIME type
    if mime_type == "image/jpeg":
        file_extension = ".jpg"
    elif mime_type == "image/png":
        file_extension = ".png"
    elif mime_type == "image/gif":
        file_extension = ".gif"
    else:
        file_extension = ".unknown"  # Should not happen, but handle it

    unique_filename = str(uuid.uuid4()) + file_extension
    new_file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    os.rename(temp_file_path, new_file_path) # Rename with correct extension

    # 4.  Option A: Read and Convert to Base64 (if NOT using a file storage service)
    # try:
    #     with open(new_file_path, "rb") as image:
    #         image_data = image.read()
    #         base64_string = base64.b64encode(image_data).decode("utf-8")
    # except Exception as e:
    #     logging.error(f"Error reading or encoding image: {e}")
    #     os.remove(new_file_path)
    #     return False
    # image_url = None # Set image_url to None if using base64

    # 4. Option B:  Use a File Storage Service (e.g., AWS S3, Google Cloud Storage, Azure Blob Storage)
    # In a real application, you would upload the file to the storage service here.
    # For this example, we'll just simulate the upload and generate a dummy URL.
    # Replace this with your actual file storage service integration.
    image_url = f"https://example.com/images/{unique_filename}"  # Dummy URL
    base64_string = None # Set base64_string to None if using image_url

    # 5. Database Insertion (using parameterized queries)
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection
        # Store the unique filename, not the original filename
        # Store either the base64 data OR the image URL, not both
        if base64_string:
            sql = "INSERT INTO images (image_name, base64_data, user_id) VALUES (?, ?, ?)"
            cursor.execute(sql, (unique_filename, base64_string, user_id))
        else:
            sql = "INSERT INTO images (image_name, image_url, user_id) VALUES (?, ?, ?)"
            cursor.execute(sql, (unique_filename, image_url, user_id))


        conn.commit()
        logging.info("Image uploaded successfully.")
        return True

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        os.remove(new_file_path)  # Clean up the temporary file
        if conn:
            conn.close()


def create_user(username, password):
    """Creates a new user with a securely hashed password."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        password_hash = bcrypt.hash(password)  # Generate the hash
        sql = "INSERT INTO users (username, password_hash) VALUES (?, ?)"
        cursor.execute(sql, (username, password_hash))
        conn.commit()
        logging.info(f"User {username} created successfully.")
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()


def verify_password(password, password_hash):
    """Verifies a password against a stored hash."""
    try:
        return bcrypt.verify(password, password_hash)  # Check the password
    except ValueError:
        # Handle the case where the password_hash is invalid (e.g., not a bcrypt hash)
        logging.error("Invalid password hash format.")
        return False


# Example Usage (assuming you have a Flask app or similar)
if __name__ == '__main__':
    create_database()  # Initialize the database

    # Create a dummy user
    if create_user("testuser", "P@$$wOrd"):
        logging.info("Test user created.")
    else:
        logging.warning("Failed to create test user.")

    # Simulate an uploaded file (replace with actual file upload from your framework)
    # Create a dummy image file
    dummy_image_path = "dummy_image.png"
    if not os.path.exists(dummy_image_path):
        # Create a simple black image
        img = Image.new('RGB', (60, 30), color='black')
        img.save(dummy_image_path)

    class MockFile:  # Simulate a file object from a web framework
        def __init__(self, filename, path):
            self.filename = filename
            self.path = path

        def save(self, destination):
            import shutil
            shutil.copyfile(self.path, destination)

        def seek(self, offset, whence=0):
            with open(self.path, 'rb') as f:
                f.seek(offset, whence)

        def tell(self):
            with open(self.path, 'rb') as f:
                return f.seek(0, os.SEEK_END)

    mock_image_file = MockFile("test_image.png", dummy_image_path)

    user_id = 1  # Replace with the actual user ID from your authentication system

    if upload_image(mock_image_file, user_id):
        logging.info("Image upload simulation successful.")
    else:
        logging.warning("Image upload simulation failed.")

