import os
import tempfile
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_FILE_EXTENSIONS = ['.json', '.txt', '.csv']  # Example allowlist
SAFE_DIRECTORY = '/tmp/safe_results'  # Define a safe directory

def is_path_traversal(filepath):
    """
    Check if the filepath contains path traversal sequences.
    """
    if '..' in filepath:
        logging.warning(f"Path traversal detected in filepath: {filepath}")
        return True
    return False

def is_single_path_component(filepath):
    """
    Check if the filepath contains path separators or ".." sequences.
    """
    if '/' in filepath or '\\' in filepath or '..' in filepath:
        logging.warning(f"Invalid path component detected in filepath: {filepath}")
        return True
    return False

def is_valid_filepath(filepath):
    """
    Validate the filepath against security guidelines.
    """
    if not filepath:
        logging.error("Filepath cannot be empty.")
        return False

    if is_path_traversal(filepath):
        return False

    if is_single_path_component(filepath):
        return False

    if '.' not in filepath:
        logging.error("Filepath must contain a file extension.")
        return False

    if filepath.count('.') > 1:
        logging.error("Filepath contains more than one '.' character.")
        return False

    _, file_extension = os.path.splitext(filepath)
    if file_extension.lower() not in ALLOWED_FILE_EXTENSIONS:
        logging.error(f"File extension {file_extension} is not allowed.")
        return False

    if not os.path.abspath(os.path.join(SAFE_DIRECTORY, filepath)).startswith(os.path.abspath(SAFE_DIRECTORY)):
        logging.error(f"Filepath is not within the safe directory: {SAFE_DIRECTORY}")
        return False

    return True

def write_results(results, filename="results.json"):
    """
    Create a temporary file within a safe directory and write the results to it.
    """
    if not os.path.exists(SAFE_DIRECTORY):
        try:
            os.makedirs(SAFE_DIRECTORY, exist_ok=True)  # Create the safe directory if it doesn't exist
            os.chmod(SAFE_DIRECTORY, 0o700)  # Set permissions (read, write, execute for owner only)
        except OSError as e:
            logging.error(f"Failed to create safe directory: {e}")
            return None

    filepath = os.path.join(SAFE_DIRECTORY, filename)

    if not is_valid_filepath(filepath):
        logging.error(f"Invalid filepath: {filepath}")
        return None

    try:
        # Open the file in a secure manner
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=4)  # Use json.dump for structured data
        logging.info(f"Results written to: {filepath}")
        return filepath
    except Exception as e:
        logging.error(f"Error writing to file: {e}")
        return None

if __name__ == '__main__':
    # Example usage:
    results_data = {"data": [1, 2, 3, 4, 5]}
    file_path = write_results(results_data, "my_results.json")

    if file_path:
        print(f"Results written to: {file_path}")
    else:
        print("Failed to write results.")

    # Example of an invalid filepath:
    invalid_file_path = write_results(results_data, "../../../evil.txt")  # Path traversal attempt
    if invalid_file_path:
        print(f"Results written to: {invalid_file_path}")
    else:
        print("Failed to write results (as expected).")

    invalid_file_path2 = write_results(results_data, "evil/evil.txt")  # Path traversal attempt
    if invalid_file_path2:
        print(f"Results written to: {invalid_file_path2}")
    else:
        print("Failed to write results (as expected).")

