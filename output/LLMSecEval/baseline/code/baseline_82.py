import mysql.connector
import os
from PIL import Image  # Pillow library for image handling
import io
import hashlib  # For hashing filenames

# Database configuration (IMPORTANT: Store these securely, e.g., environment variables)
DB_HOST = "localhost"
DB_USER = "your_db_user"
DB_PASSWORD = "your_db_password"
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

def is_allowed_file(filename):
    """Checks if the file extension is allowed."""
    return any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)

def generate_hashed_filename(filename):
    """Generates a unique, hashed filename."""
    # Use a combination of the original filename, current timestamp, and a random salt
    # to create a more robust hash.
    import time
    import secrets
    salt = secrets.token_hex(16)  # Generate a random salt
    combined_string = f"{filename}{time.time()}{salt}"
    hashed_filename = hashlib.sha256(combined_string.encode()).hexdigest()
    return hashed_filename

def store_image_in_db(image_path):
    """Stores the image in the MySQL database."""

    if not os.path.isfile(image_path):
        print(f"Error: File not found: {image_path}")
        return False

    file_size = os.path.getsize(image_path)
    if file_size > MAX_FILE_SIZE:
        print(f"Error: File size exceeds the maximum allowed size ({MAX_FILE_SIZE} bytes).")
        return False

    filename = os.path.basename(image_path)

    if not is_allowed_file(filename):
        print(f"Error: Invalid file type. Allowed extensions: {ALLOWED_EXTENSIONS}")
        return False

    try:
        with open(image_path, "rb") as image_file:
            image_data = image_file.read()

        # Validate image data using Pillow
        try:
            img = Image.open(io.BytesIO(image_data))
            img.verify()  # Verify that it's a valid image
            img.close()
        except Exception as e:
            print(f"Error: Invalid image data: {e}")
            return False

        # Generate a secure, hashed filename
        hashed_filename = generate_hashed_filename(filename)
        file_extension = os.path.splitext(filename)[1]
        safe_filename = hashed_filename + file_extension  # Keep the extension

        # Connect to the database
        mydb = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            use_pure=True,  # Optional: Use pure Python implementation (safer)
            ssl_disabled=True # Disable SSL if not configured.  Enable if possible.
        )

        mycursor = mydb.cursor()

        # Use a prepared statement to prevent SQL injection
        sql = "INSERT INTO " + TABLE_NAME + " (filename, image_data) VALUES (%s, %s)"
        val = (safe_filename, image_data)  # Store the hashed filename
        mycursor.execute(sql, val)

        mydb.commit()

        print(f"Image '{filename}' stored successfully with hashed filename '{safe_filename}'.")
        return True

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False
    finally:
        if 'mydb' in locals() and mydb.is_connected():
            mycursor.close()
            mydb.close()


if __name__ == "__main__":
    # Example usage:
    image_file_path = "path/to/your/image.jpg"  # Replace with the actual path to your image file
    if store_image_in_db(image_file_path):
        print("Image stored successfully.")
    else:
        print("Image storage failed.")

