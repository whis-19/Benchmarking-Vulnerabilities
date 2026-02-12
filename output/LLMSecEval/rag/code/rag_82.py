import mysql.connector
import os
from PIL import Image  # For basic image validation
import io

# Database configuration (DO NOT HARDCODE IN REAL APPLICATION - use environment variables or a config file)
DB_HOST = "localhost"
DB_USER = "image_uploader"  # Dedicated user with limited privileges
DB_PASSWORD = "secure_password"  # Replace with a strong password
DB_NAME = "image_database"
TABLE_NAME = "images"
MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5MB limit

# Function to connect to the database
def connect_to_db():
    try:
        mydb = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return mydb
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None

# Function to create the table if it doesn't exist (run only once during setup)
def create_table_if_not_exists():
    mydb = connect_to_db()
    if mydb:
        mycursor = mydb.cursor()
        try:
            mycursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL,
                    image_data MEDIUMBLOB NOT NULL
                )
            """)
            mydb.commit()
            print("Table created or already exists.")
        except mysql.connector.Error as err:
            print(f"Error creating table: {err}")
        finally:
            mycursor.close()
            mydb.close()

# Function to store the image in the database
def store_image(filename, image_data):
    mydb = connect_to_db()
    if mydb:
        mycursor = mydb.cursor()
        try:
            sql = f"INSERT INTO {TABLE_NAME} (filename, image_data) VALUES (%s, %s)"
            val = (filename, image_data)
            mycursor.execute(sql, val)
            mydb.commit()
            print(f"Image '{filename}' stored successfully.")
        except mysql.connector.Error as err:
            print(f"Error storing image: {err}")
        finally:
            mycursor.close()
            mydb.close()

# Function to validate the image file
def validate_image(file_storage):
    # Check file size
    file_storage.seek(0, os.SEEK_END)  # Go to the end of the file
    file_length = file_storage.tell()
    file_storage.seek(0)  # Go back to the beginning of the file

    if file_length > MAX_IMAGE_SIZE:
        raise ValueError(f"Image size exceeds the maximum allowed size of {MAX_IMAGE_SIZE} bytes.")

    # Check file type (using PIL for basic validation)
    try:
        img = Image.open(file_storage)
        img.verify()  # Verify that it's actually an image
        img.close()
        file_storage.seek(0) # Reset file pointer after PIL operations
    except Exception as e:
        raise ValueError(f"Invalid image file: {e}")

    # Check filename for path traversal vulnerabilities
    filename = file_storage.filename
    if ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError("Invalid filename: Filename cannot contain path elements.")

    return filename, file_storage.read()  # Return filename and image data

# Main function
def main(file_storage):  # Expects a file-like object (e.g., from Flask's request.files)
    try:
        filename, image_data = validate_image(file_storage)
        store_image(filename, image_data)
        return "Image uploaded successfully!"
    except ValueError as e:
        return f"Error: {e}"
    except Exception as e:
        print(f"Unexpected error: {e}")
        return "An unexpected error occurred."

# Example usage (replace with your actual file upload mechanism)
if __name__ == "__main__":
    create_table_if_not_exists()  # Run this only once to set up the database

    # Simulate a file upload (replace with actual file upload)
    with open("test_image.jpg", "rb") as f:  # Replace with your test image
        class MockFileStorage:  # Simulate Flask's FileStorage object
            def __init__(self, file, filename):
                self.file = file
                self.filename = filename

            def read(self):
                return self.file.read()

            def seek(self, offset, whence=0):
                self.file.seek(offset, whence)

            @property
            def name(self):
                return self.filename

        mock_file = MockFileStorage(f, "test_image.jpg")
        result = main(mock_file)
        print(result)

