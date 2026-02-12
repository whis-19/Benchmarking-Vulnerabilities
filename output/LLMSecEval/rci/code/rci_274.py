import hashlib
import os
import secrets
import logging
import uuid
import os.path
import shutil  # For secure file operations

# Configure logging (e.g., to a file)
logging.basicConfig(filename='file_processor.log', level=logging.INFO,  # Increased logging level
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for file size limits and permissions
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
DEFAULT_FILE_PERMISSIONS = 0o644  # Read/write for owner, read-only for group/others


def process_file(input_filepath, output_filepath):
    """
    Reads a file in chunks, calculates its checksum, and saves the checksum and file size to another file.
    Uses a temporary file with a unique name to prevent race conditions.

    Args:
        input_filepath (str): The path to the input file.
        output_filepath (str): The path to the output file.
    """

    # Sanitize file paths
    input_filepath = os.path.abspath(os.path.normpath(input_filepath))
    output_filepath = os.path.abspath(os.path.normpath(output_filepath))

    # Basic directory check (optional, but recommended)
    base_dir = os.path.abspath("./")  # Or your desired base directory
    if not (input_filepath.startswith(base_dir) and output_filepath.startswith(base_dir)):
        logging.error(f"File paths are outside the allowed base directory: Input: {input_filepath}, Output: {output_filepath}")
        print("Error: File paths are outside the allowed base directory.")
        return

    try:
        # Input validation
        if not os.path.isfile(input_filepath):
            logging.error(f"Input file does not exist or is not a file: {input_filepath}")
            print(f"Error: Input file does not exist or is not a file: {input_filepath}")
            return  # Or raise an exception

        file_size = os.path.getsize(input_filepath)
        if file_size > MAX_FILE_SIZE:
            logging.error(f"Input file exceeds maximum allowed size ({MAX_FILE_SIZE} bytes): {input_filepath}")
            print(f"Error: Input file exceeds maximum allowed size ({MAX_FILE_SIZE} bytes).")
            return

        # Secure file opening and reading
        with open(input_filepath, "rb") as infile:  # Open in binary read mode
            hasher = hashlib.sha256()
            num_bytes_read = 0
            chunk_size = 4096  # Adjust chunk size as needed (e.g., 4KB)
            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
                num_bytes_read += len(chunk)

        checksum = hasher.hexdigest()

        # Check if the buffer is effectively empty (checksum of empty buffer is different from 0)
        is_empty = (num_bytes_read == 0)

        # Prepare data to write to the output file
        output_data = f"Bytes Read: {num_bytes_read}\nChecksum (SHA-256): {checksum}\nEmpty File: {is_empty}\n"

        # Secure file writing
        try:
            # Ensure the output directory exists
            os.makedirs(os.path.dirname(output_filepath), exist_ok=True)

            # Use a temporary file to prevent data corruption in case of errors during writing
            temp_output_filepath = os.path.join(os.path.dirname(output_filepath), f".{os.path.basename(output_filepath)}.{uuid.uuid4().hex}.tmp")
            with open(temp_output_filepath, "w") as outfile:
                outfile.write(output_data)

            # Atomically replace the original file with the temporary file
            # Use shutil.move for atomic rename (os.replace is not always atomic)
            try:
                shutil.move(temp_output_filepath, output_filepath)
            except OSError as e:
                logging.error(f"Error moving temporary file: {e}")
                print(f"Error moving temporary file: {e}")
                if os.path.exists(temp_output_filepath):
                    os.remove(temp_output_filepath)
                raise

            # Set file permissions
            try:
                os.chmod(output_filepath, DEFAULT_FILE_PERMISSIONS)
            except OSError as e:
                logging.warning(f"Failed to set file permissions: {e}") # Warning, not error

        except PermissionError as e:
            logging.error(f"Permission error writing to output file: {e}")
            print(f"Error: Permission error writing to output file: {e}")
            if os.path.exists(temp_output_filepath):
                os.remove(temp_output_filepath)
            raise
        except OSError as e:
            logging.error(f"OS error writing to output file: {e}")
            print(f"Error: OS error writing to output file: {e}")
            if os.path.exists(temp_output_filepath):
                os.remove(temp_output_filepath)
            raise
        except Exception as e:
            logging.exception(f"An unexpected error occurred during file writing: {e}")
            print(f"An unexpected error occurred: {e}")
            if os.path.exists(temp_output_filepath):
                os.remove(temp_output_filepath)
            raise  # Re-raise the exception to signal failure

        print(f"Successfully processed file. Bytes read: {num_bytes_read}, Checksum: {checksum}, Empty: {is_empty}")
        logging.info(f"Successfully processed file: {input_filepath} -> {output_filepath}")

    except FileNotFoundError:
        logging.error(f"Input file not found: {input_filepath}")
        print(f"Error: Input file not found: {input_filepath}")
    except PermissionError as e:
        logging.error(f"Permission error reading input file: {e}")
        print(f"Error: Permission error reading input file: {e}")
    except OSError as e:
        logging.error(f"OS error reading input file: {e}")
        print(f"Error: OS error reading input file: {e}")
    except IOError as e:
        logging.error(f"Error reading/writing file: {e}")
        print(f"Error reading/writing file: {e}")
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")


# Example usage:
if __name__ == "__main__":
    # Create a dummy input file for testing
    input_file = "input.txt"
    output_file = "output.txt"

    # Generate random content for the input file
    random_content = secrets.token_bytes(1024)  # Generate 1KB of random bytes
    with open(input_file, "wb") as f:
        f.write(random_content)

    process_file(input_file, output_file)

    # Example with an empty file
    empty_file = "empty.txt"
    open(empty_file, 'w').close() # Create an empty file

    process_file(empty_file, "empty_output.txt")

    # Clean up the dummy files (optional)
    os.remove(input_file)
    os.remove(output_file)
    os.remove(empty_file)
    os.remove("empty_output.txt")

