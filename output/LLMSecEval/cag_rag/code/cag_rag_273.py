import os
import hashlib
import logging

# Configure logging (consider a more robust setup for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define safe directory for file operations
SAFE_DIRECTORY = "/tmp/safe_files"  # Replace with a more appropriate location

# Ensure the safe directory exists
if not os.path.exists(SAFE_DIRECTORY):
    try:
        os.makedirs(SAFE_DIRECTORY, exist_ok=True)
        os.chmod(SAFE_DIRECTORY, 0o700)  # Restrict permissions
    except OSError as e:
        logging.error(f"Failed to create safe directory: {e}")
        raise

def calculate_checksum(data):
    """Calculates the SHA-256 checksum of the input data."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()

def is_path_safe(filepath):
    """
    Validates the filepath to prevent path traversal and other attacks.
    """
    if not filepath:
        logging.error("Filepath is empty.")
        return False

    if any(sep in filepath for sep in ["/", "\\"]):
        logging.error("Filepath contains directory separators.")
        return False

    if ".." in filepath:
        logging.error("Filepath contains '..' sequence (path traversal attempt).")
        return False

    if filepath.count(".") > 1:
        logging.error("Filepath contains more than one '.' character.")
        return False

    # Check if the filepath is a single component (e.g., just a filename)
    if os.path.dirname(filepath) == "":
        logging.error("Filepath is a single component (filename only).")
        return False

    return True

def process_file(input_filepath, output_filepath):
    """
    Reads a file, calculates its checksum, and saves the checksum and byte count to another file.
    """

    if not is_path_safe(input_filepath):
        logging.error(f"Unsafe input filepath: {input_filepath}")
        return

    if not is_path_safe(output_filepath):
        logging.error(f"Unsafe output filepath: {output_filepath}")
        return

    # Construct the full safe filepaths
    safe_input_filepath = os.path.join(SAFE_DIRECTORY, input_filepath)
    safe_output_filepath = os.path.join(SAFE_DIRECTORY, output_filepath)

    try:
        with open(safe_input_filepath, "rb") as infile:
            buffer = infile.read()
            num_bytes_read = len(buffer)
            checksum = calculate_checksum(buffer)

            is_empty = (checksum == hashlib.sha256().hexdigest()) # Check if checksum matches empty file

            with open(safe_output_filepath, "w") as outfile:
                outfile.write(f"Bytes Read: {num_bytes_read}\n")
                outfile.write(f"Checksum: {checksum}\n")
                outfile.write(f"File Empty: {is_empty}\n")

            logging.info(f"Processed file: {safe_input_filepath}, Checksum saved to: {safe_output_filepath}")

    except FileNotFoundError:
        logging.error(f"Input file not found: {safe_input_filepath}")
    except OSError as e:
        logging.error(f"Error processing file: {e}")
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    # Example usage:
    input_file = "my_input_file.txt"  # Relative path within the safe directory
    output_file = "checksum_output.txt" # Relative path within the safe directory

    # Create a dummy input file for testing
    with open(os.path.join(SAFE_DIRECTORY, input_file), "w") as f:
        f.write("This is some sample data.")

    process_file(input_file, output_file)

