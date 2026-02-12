import os
import hashlib
import logging
import stat

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
SAFE_FOLDER = "/tmp/safe_files"  # Define a safe folder
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit for log file size

def calculate_checksum(data):
    """Calculates the SHA-256 checksum of the given data."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()

def is_valid_filepath(filepath):
    """
    Validates the filepath against security guidelines.

    Args:
        filepath (str): The filepath to validate.

    Returns:
        bool: True if the filepath is valid, False otherwise.
    """

    if not filepath:
        logging.error("Filepath cannot be empty.")
        return False

    if filepath.count(".") > 1:
        logging.error("Filepath contains more than one '.' character.")
        return False

    if "/" in filepath or "\\" in filepath:
        logging.error("Filepath contains directory separators.")
        return False

    if ".." in filepath:
        logging.error("Filepath contains '..' sequence.")
        return False

    # Allowlist approach (example - adapt to your needs)
    allowed_patterns = ["data.txt", "config.ini", "report.csv"]  # Example
    if filepath not in allowed_patterns:
        logging.error(f"Filepath '{filepath}' is not in the allowlist.")
        return False

    return True

def process_file(input_filepath, output_filepath):
    """
    Reads a file, calculates its checksum, and saves the checksum and byte count to another file.

    Args:
        input_filepath (str): The path to the input file.
        output_filepath (str): The path to the output file.
    """

    if not is_valid_filepath(input_filepath):
        logging.error(f"Invalid input filepath: {input_filepath}")
        return

    if not is_valid_filepath(output_filepath):
        logging.error(f"Invalid output filepath: {output_filepath}")
        return

    # Ensure safe folder exists
    os.makedirs(SAFE_FOLDER, exist_ok=True)

    # Construct full paths within the safe folder
    full_input_path = os.path.join(SAFE_FOLDER, input_filepath)
    full_output_path = os.path.join(SAFE_FOLDER, output_filepath)

    try:
        with open(full_input_path, "rb") as infile:
            buffer = infile.read()
            num_bytes_read = len(buffer)
            checksum = calculate_checksum(buffer)

            is_empty = (checksum == hashlib.sha256().hexdigest())  # Check if checksum matches empty file

            logging.info(f"File '{full_input_path}' processed. Bytes read: {num_bytes_read}, Checksum: {checksum}, Empty: {is_empty}")

    except FileNotFoundError:
        logging.error(f"Input file not found: {full_input_path}")
        return
    except Exception as e:
        logging.error(f"Error reading input file: {e}")
        return

    try:
        # Limit output file size
        if os.path.exists(full_output_path) and os.path.getsize(full_output_path) > MAX_FILE_SIZE:
            logging.warning(f"Output file '{full_output_path}' exceeds maximum size.  Not writing.")
            return

        with open(full_output_path, "a") as outfile:  # Append mode to prevent overwriting
            outfile.write(f"Input File: {input_filepath}\n")
            outfile.write(f"Bytes Read: {num_bytes_read}\n")
            outfile.write(f"Checksum: {checksum}\n")
            outfile.write(f"Empty: {is_empty}\n")
            outfile.write("-" * 20 + "\n")  # Separator for entries

        # Restrict file permissions (read/write for owner only)
        os.chmod(full_output_path, stat.S_IRUSR | stat.S_IWUSR)

        logging.info(f"Data written to output file: {full_output_path}")

    except Exception as e:
        logging.error(f"Error writing to output file: {e}")


if __name__ == "__main__":
    # Example usage:
    # Create a dummy input file for testing
    dummy_file_path = "test_input.txt"
    with open(os.path.join(SAFE_FOLDER, dummy_file_path), "w") as f:
        f.write("This is a test file.")

    process_file(dummy_file_path, "output.log")

    # Example with an invalid filepath
    process_file("../../../sensitive_data.txt", "output.log")  # This will be rejected
    process_file("valid_file.txt/../../", "output.log") # This will be rejected

