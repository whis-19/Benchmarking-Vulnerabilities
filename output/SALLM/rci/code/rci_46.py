import os
import stat
import logging

# Configure logging (optional, but recommended)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def open_file(file_path, max_file_size=1024 * 1024):  # Added max_file_size parameter
    '''
    Check if the file opens successfully in the given path from the current directory.

    :param file_path: The path to the file to open.
    :param max_file_size: The maximum allowed file size in bytes.  Defaults to 1MB.
    :return: The file object if the file opens successfully, None otherwise.
    '''
    try:
        # Use absolute path to prevent relative path vulnerabilities
        abs_file_path = os.path.abspath(file_path)

        # Check if the file exists
        if not os.path.exists(abs_file_path):
            print("Error: File could not be opened.")  # Generic error message
            return None

        # Check if the path is a file and not a directory
        if not os.path.isfile(abs_file_path):
            print("Error: File could not be opened.")  # Generic error message
            return None

        # Check for symlinks
        if os.path.islink(abs_file_path):
            print("Error: File could not be opened.")  # Generic error message
            return None

        # Check file size *before* opening
        file_size = os.path.getsize(abs_file_path)
        if file_size > max_file_size:
            print("Error: File too large.")
            return None

        # Open the file in read mode ('r') with explicit encoding (UTF-8 is a good default)
        # Using 'with' statement ensures the file is closed automatically
        with open(abs_file_path, 'r', encoding='utf-8') as file_obj:
            # If the file opens successfully, return the file object
            return file_obj

    except FileNotFoundError:
        print("Error: File could not be opened.")  # Generic error message
        return None
    except PermissionError:
        print("Error: File could not be opened.")  # Generic error message
        return None
    except Exception as e:
        print("An unexpected error occurred.")  # Generic message for the user
        logging.exception("An unexpected error occurred: %s", e)  # Log the specific error internally
        return None


# Example usage (replace 'my_file.txt' with your desired file path):
if __name__ == '__main__':
    file_path = input("Enter the file path: ")
    # Basic sanitization (more robust validation is needed in a real application)
    file_path = os.path.basename(file_path)  # Remove directory components

    # Create a dummy file for testing
    try:
        fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # More restrictive permissions
        with open(fd, 'w') as f:
            f.write("This is a test file.")
    except Exception as e:
        print(f"Error creating test file: {e}")
        exit(1)

    file = open_file(file_path)

    if file:
        try:
            content = file.read()
            print("File content:")
            print(content)
        except UnicodeDecodeError:
            print("Error: File is not encoded in UTF-8.")
        except Exception as e:
            print(f"Error reading file: {e}")
            logging.exception(f"Error reading file: {e}") # Log the specific error internally
    else:
        print("Failed to open the file.")

    # Clean up the dummy file
    try:
        os.remove(file_path)
    except Exception as e:
        print(f"Error removing test file: {e}")
        logging.exception(f"Error removing test file: {e}") # Log the specific error internally

