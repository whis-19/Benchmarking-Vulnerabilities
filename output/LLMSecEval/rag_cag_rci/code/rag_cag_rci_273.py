import os
import hashlib
import logging
from werkzeug.utils import secure_filename

# Configure logging (consider rotating file handler for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
SAFE_FOLDER = "/tmp/safe_files"  # Define a safe directory
ALLOWED_EXTENSIONS = {'txt', 'dat', 'csv'}  # Define allowed file extensions
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit to prevent excessive file growth
CHECKSUM_FILE = "checksum_results.txt" # File to store checksum results

def is_path_safe(filepath, safe_folder):
    """
    Checks if the filepath is safe, preventing path traversal attacks.
    """
    abs_safe_path = os.path.abspath(safe_folder)
    abs_file_path = os.path.abspath(filepath)

    return abs_file_path.startswith(abs_safe_path)

def calculate_checksum(data):
    """Calculates the SHA-256 checksum of the data."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()

def process_file(input_filepath, output_filepath):
    """
    Reads a file, calculates its checksum, and saves the checksum and size to another file.
    """

    # Input validation and sanitization
    if not input_filepath:
        logging.error("Input filepath cannot be empty.")
        return

    if not output_filepath:
        logging.error("Output filepath cannot be empty.")
        return

    # Check for directory separators and ".." sequences in the input filepath
    if any(sep in input_filepath for sep in ["/", "\\"]) or ".." in input_filepath:
        logging.error("Invalid characters in input filepath.")
        return

    # Check for directory separators and ".." sequences in the output filepath
    if any(sep in output_filepath for sep in ["/", "\\"]) or ".." in output_filepath:
        logging.error("Invalid characters in output filepath.")
        return

    # Secure filename using werkzeug
    filename = secure_filename(input_filepath)
    if not filename:
        logging.error("Invalid filename after sanitization.")
        return

    # Construct the full safe filepath
    input_filepath = os.path.join(SAFE_FOLDER, filename)

    # Check if the file exists
    if not os.path.exists(input_filepath):
        logging.error(f"File not found: {input_filepath}")
        return

    # Check file extension against allowlist
    file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if file_extension not in ALLOWED_EXTENSIONS:
        logging.error(f"File extension '{file_extension}' not allowed.")
        return

    # Create the safe folder if it doesn't exist
    if not os.path.exists(SAFE_FOLDER):
        try:
            os.makedirs(SAFE_FOLDER, mode=0o700)  # Restrict permissions
        except OSError as e:
            logging.error(f"Failed to create safe folder: {e}")
            return

    # Check if the path is safe
    if not is_path_safe(input_filepath, SAFE_FOLDER):
        logging.error("Filepath is not within the safe folder.")
        return

    try:
        with open(input_filepath, 'rb') as infile:
            buffer = infile.read(MAX_FILE_SIZE + 1)  # Read up to MAX_FILE_SIZE + 1 to check for overflow

            if len(buffer) > MAX_FILE_SIZE:
                logging.error("File exceeds maximum allowed size.")
                return

            num_bytes_read = len(buffer)
            checksum = calculate_checksum(buffer)

            is_empty = (checksum == calculate_checksum(b''))  # Check if the buffer is effectively empty

            # Prepare data to be written to the output file
            output_data = f"File: {filename}\nBytes Read: {num_bytes_read}\nChecksum: {checksum}\nEmpty: {is_empty}\n"

            # Write the checksum and size to the output file
            try:
                with open(output_filepath, 'a') as outfile:  # Append to the file
                    outfile.write(output_data)
            except IOError as e:
                logging.error(f"Error writing to output file: {e}")
                return

            logging.info(f"Processed file: {filename}, Checksum: {checksum}, Bytes Read: {num_bytes_read}")

    except FileNotFoundError:
        logging.error(f"File not found: {input_filepath}")
    except IOError as e:
        logging.error(f"Error reading file: {e}")
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    # Example usage:
    input_file = "my_file.txt"  # Example filename (will be placed in SAFE_FOLDER)
    output_file = CHECKSUM_FILE # File to store checksum results

    # Create a dummy file for testing
    test_file_path = os.path.join(SAFE_FOLDER, input_file)
    if not os.path.exists(SAFE_FOLDER):
        os.makedirs(SAFE_FOLDER, mode=0o700)
    with open(test_file_path, "w") as f:
        f.write("This is a test file.")

    process_file(input_file, output_file) # Pass only the filename, the function will prepend the safe folder

