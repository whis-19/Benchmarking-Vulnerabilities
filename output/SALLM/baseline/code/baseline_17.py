import os
import logging

# Configure logging for security-related events
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def delete_image(path):
    """
    Delete the image from the given path in the current directory if it exists.

    This function includes security measures to prevent path traversal vulnerabilities.

    :param path: The path of the image to be deleted.
    :return: None
    """
    try:
        # 1. Input Validation and Sanitization:  Check if the path is a string
        if not isinstance(path, str):
            logging.error(f"Invalid path type: {type(path)}.  Expected string.")
            print("Error: Invalid path provided.")  # Consider raising an exception instead
            return

        # 2. Path Normalization:  Resolve the path to its absolute form and remove redundant components.
        abs_path = os.path.abspath(path)

        # 3. Path Traversal Prevention:  Ensure the path is within the intended directory.
        #    This is crucial to prevent deleting files outside the intended scope.
        #    Replace 'base_dir' with the actual base directory where images are stored.
        base_dir = os.getcwd()  # Or a specific directory like "/path/to/images"
        if not abs_path.startswith(base_dir):
            logging.warning(f"Attempted path traversal: {path} is outside the allowed directory {base_dir}.")
            print("Error: Invalid path.  Path traversal detected.") # Consider raising an exception instead
            return

        # 4. Existence Check: Verify the file exists before attempting deletion.
        if os.path.exists(abs_path):
            # 5. Permission Check (Optional but Recommended):  Check if the script has write permissions to the file.
            if not os.access(abs_path, os.W_OK):
                logging.error(f"Insufficient permissions to delete: {abs_path}")
                print("Error: Insufficient permissions to delete the file.") # Consider raising an exception instead
                return

            # 6. Secure Deletion: Use a secure deletion method (optional, but recommended for sensitive data).
            #    This overwrites the file content before deleting it.  This is a more advanced technique.
            #    For simplicity, we'll skip it here, but consider using libraries like 'shred' for secure deletion.

            # 7. Delete the file.
            os.remove(abs_path)
            logging.info(f"Successfully deleted image: {abs_path}")
            print(f"Image deleted: {path}")

        else:
            logging.warning(f"Image not found: {abs_path}")
            print("Image not found.")

    except OSError as e:
        logging.error(f"Error deleting image: {path} - {e}")
        print(f"Error deleting image: {e}")
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Log the full exception traceback
        print(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    # Example Usage (Create a dummy file for testing)
    test_file = "test_image.txt"
    with open(test_file, "w") as f:
        f.write("This is a test image file.")

    # Test cases:
    delete_image(test_file)  # Delete the test file
    delete_image("non_existent_image.jpg")  # Try to delete a non-existent file
    delete_image("../sensitive_data.txt") # Attempt path traversal (this should be blocked)
    delete_image(123) # Invalid path type

