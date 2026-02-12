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

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    os.chmod(UPLOAD_FOLDER, 0o750)  # Set secure permissions (owner read/write/execute, group read/execute, others none)


def allowed_file(filename):
    """Check if the file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def store_image_in_db(image_file, filename_input):
    """
    Stores an image file in a MySQL database.

    Args:
        image_file: The image file to store (werkzeug.datastructures.FileStorage).
        filename_input: The user-provided filename.
    """

    try:
        # 1. Input Validation and Sanitization (Filename)
        if not filename_input:
            raise ValueError("Filename cannot be empty.")

        if "/" in filename_input or "\\" in filename_input or ".." in filename_input:
            raise ValueError("Invalid characters in filename.")

        if filename_input.count(".") > 1:
            raise ValueError("Filename contains too many '.' characters.")

        # Use werkzeug.utils.secure_filename to sanitize the filename
        filename = secure_filename(filename_input)

        if not filename:
            raise ValueError("Filename is invalid after sanitization.")

        # 2. File Extension Validation
        if not allowed_file(filename):
            raise ValueError("Invalid file extension.")

        # 3. Construct Safe File Path
        filepath = os.path.join(UPLOAD_FOLDER, filename)

        # 4. Save the file to the safe location
        try:
            image_file.save(filepath)
        except Exception as e:
            raise ValueError(f"Failed to save file: {e}")

        # 5. Read the image data
        try:
            with open(filepath, "rb") as f:
                image_data = f.read()
        except FileNotFoundError:
            raise ValueError("File not found after saving.")
        except Exception as e:
            raise ValueError(f"Error reading file: {e}")

        # 6. Database Connection and Insertion (Parameterized Query)
        try:
            connection = mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
            )
            cursor = connection.cursor()

            # SQL query with parameterized query
            query = "INSERT INTO images (filename, image_data) VALUES (%s, %s)"
            values = (filename, image_data)

            cursor.execute(query, values)
            connection.commit()

            print(f"Image '{filename}' stored successfully in the database.")

        except mysql.connector.Error as err:
            print(f"Database error: {err}")
            raise  # Re-raise the exception to be handled by the caller

        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

    except ValueError as e:
        print(f"Input validation error: {e}")
        raise  # Re-raise the exception to be handled by the caller
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise  # Re-raise the exception to be handled by the caller


if __name__ == "__main__":
    # Example usage (replace with your actual file upload mechanism)
    # This is just a simulation for testing purposes.  In a real application,
    # you would get the file from a web form or API request.

    # Create a dummy image file for testing
    with open("test_image.jpg", "wb") as f:
        f.write(b"Dummy image data")  # Replace with actual image data

    class MockFile:
        def __init__(self, filename):
            self.filename = filename

        def save(self, filepath):
            # Simulate saving the file
            with open(self.filename, "rb") as source_file:
                with open(filepath, "wb") as dest_file:
                    dest_file.write(source_file.read())

    try:
        # Simulate a file upload
        image_file = MockFile("test_image.jpg")
        user_provided_filename = "my_image.png"  # Simulate user input

        store_image_in_db(image_file, user_provided_filename)

    except ValueError as e:
        print(f"Error processing image: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    finally:
        # Clean up the dummy image file
        if os.path.exists("test_image.jpg"):
            os.remove("test_image.jpg")

        # Clean up the uploaded file if it exists
        uploaded_file_path = os.path.join(UPLOAD_FOLDER, "my_image.png")
        if os.path.exists(uploaded_file_path):
            os.remove(uploaded_file_path)

