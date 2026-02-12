import os
import hashlib

# Constants
SAFE_FOLDER = "/tmp/safe_files"  # Define a safe folder
ALLOWED_EXTENSIONS = [".txt", ".dat", ".csv"]  # Define allowed file extensions
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit
CHECKSUM_FILE = os.path.join(SAFE_FOLDER, "checksum_results.txt")


def calculate_checksum_and_save(input_file_path, checksum_file_path=CHECKSUM_FILE):
    """
    Reads a file, calculates its checksum, and saves the checksum and file size
    to another file.  Handles potential security vulnerabilities.

    Args:
        input_file_path (str): The path to the input file.
        checksum_file_path (str): The path to the file where checksum results are saved.
                                   Defaults to CHECKSUM_FILE.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """

    # 1. Validate and sanitize file paths
    if not is_safe_path(input_file_path):
        print("Error: Input file path is not safe.")
        return False

    if not is_safe_path(checksum_file_path):
        print("Error: Checksum file path is not safe.")
        return False

    # 2. Prevent path traversal attacks
    if ".." in input_file_path or ".." in checksum_file_path:
        print("Error: Path traversal detected.")
        return False

    # 3. Use allowlists for file extensions and locations
    if not is_allowed_extension(input_file_path, ALLOWED_EXTENSIONS):
        print(f"Error: File extension not allowed. Allowed extensions: {ALLOWED_EXTENSIONS}")
        return False

    if not checksum_file_path.startswith(SAFE_FOLDER):
        print("Error: Checksum file must be in the safe folder.")
        return False

    try:
        # Create the safe folder if it doesn't exist
        os.makedirs(SAFE_FOLDER, exist_ok=True)

        # 4. Implement proper file permissions and access controls (example: restrict access)
        # This is just an example; adjust permissions as needed for your environment.
        os.chmod(SAFE_FOLDER, 0o700)  # Owner read/write/execute, no access for others

        # Open the input file in binary read mode
        with open(input_file_path, "rb") as input_file:
            # Read the file contents into a buffer, limiting the file size
            buffer = input_file.read(MAX_FILE_SIZE)
            num_bytes_read = len(buffer)

            # 5. Prevent files from growing without any limit
            if num_bytes_read == MAX_FILE_SIZE and input_file.read(1):  # Check if there's more data
                print("Error: File exceeds maximum allowed size.")
                return False

            # Calculate the checksum
            checksum = hashlib.md5(buffer).hexdigest()

            # Check if the buffer is empty (checksum is 0 is not a reliable check)
            is_empty = (num_bytes_read == 0)

        # Open the checksum file in append mode
        with open(checksum_file_path, "a") as checksum_file:
            # Write the number of bytes read and the checksum to the file
            checksum_file.write(f"File: {input_file_path}\n")
            checksum_file.write(f"Bytes Read: {num_bytes_read}\n")
            checksum_file.write(f"Checksum: {checksum}\n")
            checksum_file.write(f"Is Empty: {is_empty}\n")
            checksum_file.write("-" * 20 + "\n")

        print(f"Checksum saved to {checksum_file_path}")
        return True

    except FileNotFoundError:
        print(f"Error: File not found: {input_file_path}")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def is_safe_path(file_path):
    """
    Checks if a file path is safe.  This is a basic check; more robust validation
    might be needed depending on the application.

    Args:
        file_path (str): The file path to check.

    Returns:
        bool: True if the path is considered safe, False otherwise.
    """
    # 11. Do not allow more than a single "." character in a user-provided filepath.
    if file_path.count(".") > 1:
        return False

    # Check for potentially dangerous characters or patterns
    if any(char in file_path for char in ["<", ">", "|", ";", "&", "$"]):
        return False

    return True


def is_allowed_extension(file_path, allowed_extensions):
    """
    Checks if a file has an allowed extension.

    Args:
        file_path (str): The path to the file.
        allowed_extensions (list): A list of allowed file extensions.

    Returns:
        bool: True if the file has an allowed extension, False otherwise.
    """
    _, ext = os.path.splitext(file_path)
    return ext.lower() in allowed_extensions


# Example usage:
if __name__ == "__main__":
    # Create a dummy input file for testing
    test_file = os.path.join(SAFE_FOLDER, "test_file.txt")
    os.makedirs(SAFE_FOLDER, exist_ok=True)
    with open(test_file, "w") as f:
        f.write("This is a test file.")

    # Calculate the checksum and save it to the checksum file
    success = calculate_checksum_and_save(test_file)

    if success:
        print("Checksum calculation and save successful.")
    else:
        print("Checksum calculation and save failed.")

    # Example with an invalid file path
    success = calculate_checksum_and_save("../../../etc/passwd")  # Example of a path traversal attempt
    if success:
        print("Checksum calculation and save successful.")
    else:
        print("Checksum calculation and save failed.")

    # Example with an invalid file extension
    test_file_invalid_ext = os.path.join(SAFE_FOLDER, "test_file.exe")
    with open(test_file_invalid_ext, "w") as f:
        f.write("This is a test file with invalid extension.")
    success = calculate_checksum_and_save(test_file_invalid_ext)
    if success:
        print("Checksum calculation and save successful.")
    else:
        print("Checksum calculation and save failed.")

