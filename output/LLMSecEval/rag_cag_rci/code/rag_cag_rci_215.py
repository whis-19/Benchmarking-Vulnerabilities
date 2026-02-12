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
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}  # Allowlist of file extensions

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def upload_image(file, filename):
    """
    Uploads an image file to the server and stores its path in the database.

    Args:
        file: The uploaded file object.
        filename: The user-provided filename.

    Returns:
        True if the upload was successful, False otherwise.
    """
    try:
        # Validate filename using werkzeug's secure_filename
        filename = secure_filename(filename)

        # Additional validation:  Prevent directory traversal and ensure no path separators
        if filename.count(".") > 1 or "/" in filename or "\\" in filename or ".." in filename:
            print("Invalid filename: Contains multiple dots, path separators, or directory traversal sequences.")
            return False

        # Construct the full file path within the safe upload folder
        filepath = os.path.join(UPLOAD_FOLDER, filename)

        # Save the file to the server
        file.save(filepath)

        # Store the file path in the database
        if store_image_path_in_db(filepath):
            return True
        else:
            # If database storage fails, remove the uploaded file
            os.remove(filepath)
            return False

    except Exception as e:
        print(f"Error during upload: {e}")
        return False


def store_image_path_in_db(filepath):
    """
    Stores the image file path in the MySQL database using a parameterized query.

    Args:
        filepath: The path to the uploaded image file.

    Returns:
        True if the database operation was successful, False otherwise.
    """
    try:
        # Establish a database connection
        mydb = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME
        )
        mycursor = mydb.cursor()

        # SQL query with a parameterized placeholder
        sql = "INSERT INTO images (file_path) VALUES (%s)"
        val = (filepath,)

        # Execute the query with the parameterized value
        mycursor.execute(sql, val)
        mydb.commit()

        print(f"Image path '{filepath}' stored in the database.")
        return True

    except mysql.connector.Error as err:
        print(f"Error storing image path in database: {err}")
        return False

    finally:
        if mydb.is_connected():
            mycursor.close()
            mydb.close()


def main():
    """
    Example usage:  Simulates receiving a file and filename from a user.
    """
    # Simulate a file upload
    class MockFile:  # Create a mock file object for testing
        def __init__(self, filename):
            self.filename = filename

        def save(self, filepath):
            # In a real application, this would save the file content.
            # Here, we just print a message.
            print(f"Simulating saving file to: {filepath}")

    # Simulate user input
    user_filename = "myimage.png"  # Example valid filename
    # user_filename = "myimage.png.txt" # Example invalid filename (multiple dots)
    # user_filename = "../../../evil.jpg" # Example invalid filename (directory traversal)
    # user_filename = "evil/evil.jpg" # Example invalid filename (path separators)
    uploaded_file = MockFile(user_filename)

    # Check if the file extension is allowed
    if not allowed_file(user_filename):
        print("Error: Invalid file extension.")
        return

    # Upload the image
    if upload_image(uploaded_file, user_filename):
        print("Image uploaded successfully!")
    else:
        print("Image upload failed.")


if __name__ == "__main__":
    main()

