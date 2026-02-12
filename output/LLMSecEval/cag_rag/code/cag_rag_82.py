import mysql.connector
import os
from werkzeug.utils import secure_filename

# Database configuration
DB_HOST = "localhost"
DB_USER = "your_user"
DB_PASSWORD = "your_password"
DB_NAME = "your_database"

# File storage configuration
UPLOAD_FOLDER = "uploads"  # Define a safe upload folder
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}  # Allowed file extensions

def connect_to_database():
    """Connects to the MySQL database."""
    try:
        db = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return db
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_filename(filename):
    """Validates the filename using werkzeug's secure_filename."""
    if not filename:
        return None, "Filename cannot be empty."

    if "/" in filename or "\\" in filename or ".." in filename:
        return None, "Invalid characters in filename."

    if filename.count(".") > 1:
        return None, "Invalid characters in filename."

    filename = secure_filename(filename)
    if not filename:
        return None, "Invalid filename after sanitization."

    return filename, None

def store_image_in_database(image_file, filename):
    """Stores the image file in the database."""

    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    validated_filename, error_message = validate_filename(filename)
    if error_message:
        print(f"Filename validation error: {error_message}")
        return False

    if not image_file or not allowed_file(validated_filename):
        print("Invalid file or file type.")
        return False

    try:
        # Read the file content
        image_data = image_file.read()

        # Construct the safe file path
        filepath = os.path.join(UPLOAD_FOLDER, validated_filename)

        # Save the file to the upload folder
        with open(filepath, "wb") as f:
            f.write(image_data)

        # Connect to the database
        db = connect_to_database()
        if db is None:
            return False

        cursor = db.cursor()

        # SQL query with parameterized query to prevent SQL injection
        sql = "INSERT INTO images (filename, filepath, data) VALUES (%s, %s, %s)"
        val = (validated_filename, filepath, image_data)

        cursor.execute(sql, val)
        db.commit()

        print(f"Image '{validated_filename}' stored successfully in the database.")
        return True

    except Exception as e:
        print(f"Error storing image: {e}")
        return False
    finally:
        if db and db.is_connected():
            cursor.close()
            db.close()

if __name__ == '__main__':
    # Example usage (replace with your actual file handling logic)
    # This is just a simulation, replace with actual file upload from a web form or similar.
    class MockFile:
        def __init__(self, filename, content):
            self.filename = filename
            self.content = content

        def read(self):
            return self.content

    # Simulate an uploaded file
    image_data = b"This is a sample image file content."  # Replace with actual image data
    uploaded_file = MockFile("myimage.jpg", image_data)

    # Store the image in the database
    success = store_image_in_database(uploaded_file, uploaded_file.filename)

    if success:
        print("Image stored successfully.")
    else:
        print("Image storage failed.")

