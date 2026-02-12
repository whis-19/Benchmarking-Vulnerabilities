def validate_image(file_storage):
    """
    Validates the uploaded image file.

    Args:
        file_storage:  The uploaded file object (e.g., from Flask's request.files).

    Returns:
        True if the image is valid, False otherwise.  Raises exceptions for specific errors.
    """
    # Check file size
    file_storage.seek(0, os.SEEK_END)  # Go to the end of the file
    file_size = file_storage.tell()
    file_storage.seek(0)  # Reset file pointer to the beginning

    if file_size > MAX_FILE_SIZE:
        logging.warning(f"File size validation failed: File size {file_size} exceeds maximum allowed size {MAX_FILE_SIZE}")
        raise ValueError("File size exceeds the maximum allowed size.")

    # Check file type (MIME type) - crucial for security
    content_type = file_storage.content_type
    if content_type not in ALLOWED_IMAGE_TYPES:
        logging.warning(f"File type validation failed: Invalid file type {content_type}. Allowed types: {', '.join(ALLOWED_IMAGE_TYPES)}")
        raise ValueError("Invalid file type. Allowed types: " + ", ".join(ALLOWED_IMAGE_TYPES))

    # Validate image content using PIL (Pillow)
    try:
        img = Image.open(file_storage)
        img.verify()  # Verify that it's actually an image
        img.close()
        # file_storage.seek(0)  # Redundant - already at the beginning
    except Exception as e:
        logging.warning(f"Image content validation failed: {e}")
        raise ValueError("Invalid image content: " + str(e))

    return True


def upload_image(file_storage, user_id):  # user_id is now mandatory
    """
    Uploads an image to the database.

    Args:
        file_storage: The uploaded file object (e.g., from Flask's request.files).
        user_id: The ID of the user uploading the image.  Used for access control.  **Mandatory.**

    Returns:
        True if the upload was successful, False otherwise.
    """
    if user_id is None:
        logging.error("User ID is required for image upload.")
        raise ValueError("User ID is required for image upload.")

    try:
        # 1. Validate the image
        validate_image(file_storage)

        # 2. Read the image data
        image_data = file_storage.read()
        # file_storage.seek(0) # Redundant - already at the beginning

        # 3. Convert to base64
        base64_image = base64.b64encode(image_data).decode("utf-8")

        # 4. Get the image name
        image_name = file_storage.filename

        # 5. Insert into the database using parameterized query
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        #  Important: Use parameterized queries to prevent SQL injection
        cursor.execute(
            "INSERT INTO images (image_name, image_data, user_id) VALUES (?, ?, ?)",
            (image_name, base64_image, user_id),
        )

        conn.commit()
        conn.close()

        logging.info(f"Image '{image_name}' uploaded successfully by user {user_id}.")
        return True

    except ValueError as e:
        logging.error(f"Validation error: {e}")
        return False
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False


# Example usage (assuming you have a Flask app or similar)
if __name__ == "__main__":
    # **IMPORTANT:** If you are implementing user authentication, *never* store passwords in plain text.
    # Use a strong hashing algorithm like bcrypt or Argon2 to securely store passwords.

    # **IMPORTANT:**  Consider implementing rate limiting and request size limits to protect against
    # Denial of Service (DoS) attacks.

    create_database()  # Initialize the database

    # In a real application, use a connection pool for better performance.
    # Example using a library like 'sqlite3.Pool' (requires installation):
    # from sqlite3.Pool import Pool
    # db_pool = Pool(DATABASE_PATH, max_connections=5)
    # conn = db_pool.get()
    # ... use the connection ...
    # db_pool.release(conn)

    # Simulate an uploaded file (replace with actual file upload)
    with open("test_image.png", "rb") as f:  # Replace with a real image file
        image_data = f.read()
        # Create a mock file-like object
        class MockFileStorage:
            def __init__(self, filename, content, content_type):
                self.filename = filename
                self.content = content
                self.content_type = content_type
                self.position = 0

            def read(self):
                return self.content

            def seek(self, offset, whence=0):
                if whence == 0:
                    self.position = offset
                elif whence == 1:
                    self.position += offset
                elif whence == 2:
                    self.position = len(self.content) + offset
                else:
                    raise ValueError("Invalid whence value")

            def tell(self):
                return self.position

        mock_file = MockFileStorage("test_image.png", image_data, "image/png")

        # Upload the image (with user ID)
        user_id = 123  # Example user ID
        try:
            if upload_image(mock_file, user_id):
                print("Image uploaded successfully!")

                # Retrieve the image data
                image_id = 1  # Assuming the image was the first one uploaded
                retrieved_data = get_image_data(image_id, user_id)

                if retrieved_data:
                    print("Image data retrieved successfully.")
                    # You can now display the image in your application
                    # (e.g., <img src="data:image/png;base64,retrieved_data">)
                else:
                    print("Failed to retrieve image data.")
            else:
                print("Image upload failed.")
        except ValueError as e:
            print(f"Upload failed: {e}")


    # Example of CSP (Content Security Policy) - configure this in your web server or application framework
    # Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self';
    # **IMPORTANT:** This is just an example.  You *must* customize this CSP to meet the specific
    # requirements of your application.  A too-restrictive CSP can break your site, while a too-permissive
    # CSP can leave you vulnerable to attacks.  Use a CSP validator and test thoroughly.

