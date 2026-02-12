import base64
import os
import sqlite3
from PIL import Image
from io import BytesIO

# Configuration - Adjust these based on your environment
DATABASE_PATH = "image_database.db"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit
UPLOAD_FOLDER = 'uploads'  # Store uploaded files temporarily for validation

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def create_database():
    """Creates the database and table if they don't exist.  Uses parameterized queries for safety."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Create the images table.  Crucially, use a specific user ID to isolate data.
        #  This assumes you have a user authentication system and a 'user_id' available.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,  -- Crucial: Associate image with a user
                image_name TEXT NOT NULL,
                image_data TEXT NOT NULL,
                upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create an index on user_id for faster queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON images (user_id)")

        conn.commit()

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


def is_allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_image_content(file_path):
    """Validates the image content to prevent malicious files.
    Uses PIL to attempt to open the image and check for errors.
    """
    try:
        img = Image.open(file_path)
        img.verify()  # Verify that it's actually an image
        # Optionally, check image dimensions, color mode, etc.
        return True
    except Exception as e:
        print(f"Image validation failed: {e}")
        return False


def upload_image(user_id, image_file):
    """
    Uploads an image, converts it to base64, and stores it in the database.
    Uses parameterized queries to prevent SQL injection.
    Validates file type and size.
    """
    if not image_file:
        return "No file uploaded."

    filename = image_file.filename

    if not is_allowed_file(filename):
        return "Invalid file type. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS)

    # Save the file temporarily for validation
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    image_file.save(file_path)

    # Check file size
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        os.remove(file_path)  # Remove the temporary file
        return "File size exceeds the limit of " + str(MAX_FILE_SIZE / (1024 * 1024)) + " MB."

    # Validate image content
    if not validate_image_content(file_path):
        os.remove(file_path)  # Remove the temporary file
        return "Invalid image content."

    try:
        with open(file_path, "rb") as image:
            image_data = image.read()
            image_base64 = base64.b64encode(image_data).decode('utf-8')

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection.  Crucially, filter by user_id.
        cursor.execute(
            "INSERT INTO images (user_id, image_name, image_data) VALUES (?, ?, ?)",
            (user_id, filename, image_base64)
        )
        conn.commit()
        return "Image uploaded successfully."

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "Error uploading image to the database."
    finally:
        if conn:
            conn.close()
        os.remove(file_path)  # Remove the temporary file after processing


def get_images_for_user(user_id):
    """Retrieves images for a specific user.  This is crucial for data isolation."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection and filter by user_id.
        cursor.execute("SELECT image_name, image_data FROM images WHERE user_id = ?", (user_id,))
        rows = cursor.fetchall()
        return rows  # Returns a list of tuples (image_name, image_data)

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        if conn:
            conn.close()


# Example Usage (replace with your actual user authentication and file handling)
if __name__ == '__main__':
    create_database()  # Ensure the database exists

    # Simulate a user ID (in a real application, this would come from authentication)
    current_user_id = 123

    # Simulate an uploaded file (replace with your actual file upload mechanism)
    # For testing, create a dummy image file:
    # with open("test_image.png", "wb") as f:
    #     f.write(b"dummy image data")  # Replace with actual image data

    class MockFile:  # Simulate a file object from a web framework
        def __init__(self, filename):
            self.filename = filename

        def save(self, path):
            # In a real application, this would save the uploaded file to the specified path.
            # For this example, we just copy the dummy file.
            import shutil
            shutil.copyfile("test_image.png", path)  # Replace with your actual file

    # Create a dummy image file if it doesn't exist
    if not os.path.exists("test_image.png"):
        with open("test_image.png", "wb") as f:
            f.write(b"dummy image data")

    uploaded_file = MockFile("test_image.png")

    # Upload the image
    upload_result = upload_image(current_user_id, uploaded_file)
    print(upload_result)

    # Retrieve images for the user
    user_images = get_images_for_user(current_user_id)
    print("Images for user:", user_images)

    # Example of displaying an image (replace with your actual display logic)
    if user_images:
        image_name, image_data = user_images[0]
        print(f"Displaying image: {image_name}")
        # In a real application, you would decode the base64 data and display the image in a web page.
        # For example, in HTML:
        # <img src="data:image/png;base64,{{ image_data }}" alt="{{ image_name }}">

