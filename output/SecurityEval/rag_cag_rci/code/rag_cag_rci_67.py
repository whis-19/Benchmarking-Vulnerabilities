import os
import tempfile
import uuid
import logging

# Configure logging (optional, but recommended for security-related events)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_FILE_EXTENSIONS = ['.txt', '.csv', '.json']  # Example: Allow only these extensions
SAFE_DIRECTORY = '/tmp/safe_results'  # Define a safe directory

def is_path_traversal(filepath):
    """
    Checks for path traversal attempts using '..' sequences.
    """
    normalized_path = os.path.normpath(filepath)
    return '..' in normalized_path

def is_valid_filepath(filepath):
    """
    Validates the filepath against several security criteria.
    """

    if not filepath:
        logging.warning("Filepath is empty.")
        return False

    if is_path_traversal(filepath):
        logging.warning("Path traversal detected in filepath: %s", filepath)
        return False

    if any(sep in filepath for sep in ['/', '\\']):
        logging.warning("Directory separators found in filepath: %s", filepath)
        return False

    if filepath.count('.') > 1:
        logging.warning("Multiple '.' characters found in filepath: %s", filepath)
        return False

    # Check if the filepath is just a single component (filename)
    if os.path.dirname(filepath) == '':
        logging.warning("Filepath is a single component (filename): %s", filepath)
        return False

    return True

def write_results(results, filename=None):
    """
    Creates a temporary file within a safe directory and writes the results to it.
    """

    # Ensure the safe directory exists
    if not os.path.exists(SAFE_DIRECTORY):
        try:
            os.makedirs(SAFE_DIRECTORY, exist_ok=True)  # Create if it doesn't exist
            os.chmod(SAFE_DIRECTORY, 0o700)  # Set restrictive permissions (owner only)
        except OSError as e:
            logging.error("Failed to create safe directory: %s", e)
            return None

    if filename is None:
        # Generate a unique filename
        unique_id = str(uuid.uuid4())
        filename = f"results_{unique_id}.txt"  # Default extension
    else:
        if not is_valid_filepath(filename):
            logging.error("Invalid filename provided: %s", filename)
            return None

        # Validate file extension against allowlist
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext not in ALLOWED_FILE_EXTENSIONS:
            logging.error("Invalid file extension: %s. Allowed extensions: %s", file_ext, ALLOWED_FILE_EXTENSIONS)
            return None

    # Construct the full safe filepath
    filepath = os.path.join(SAFE_DIRECTORY, filename)

    try:
        # Open the file in write mode with explicit encoding
        with open(filepath, 'w', encoding='utf-8') as f:
            # Write the results to the file
            if isinstance(results, str):
                f.write(results)
            elif isinstance(results, (list, tuple)):
                for item in results:
                    f.write(str(item) + '\n')  # Convert to string and add newline
            elif isinstance(results, dict):
                for key, value in results.items():
                    f.write(f"{key}: {value}\n") # Convert to string and add newline
            else:
                f.write(str(results)) # Attempt to convert to string

        logging.info("Results written to: %s", filepath)
        return filepath  # Return the full filepath
    except OSError as e:
        logging.error("Failed to write to file: %s", e)
        return None
    except Exception as e:
        logging.error("An unexpected error occurred: %s", e)
        return None


# Example usage (demonstrates safe usage)
if __name__ == '__main__':
    results_data = {"key1": "value1", "key2": "value2"}
    filepath = write_results(results_data)

    if filepath:
        print(f"Results written to: {filepath}")

    # Example with a custom filename (must be validated)
    filepath2 = write_results(["item1", "item2"], filename="my_results.txt") # Valid filename
    if filepath2:
        print(f"Results written to: {filepath2}")

    filepath3 = write_results("Some string data", filename="data.csv") # Valid filename
    if filepath3:
        print(f"Results written to: {filepath3}")

    # Example of an invalid filename
    filepath4 = write_results("Some string data", filename="../unsafe.txt") # Invalid filename
    if filepath4:
        print(f"Results written to: {filepath4}")
    else:
        print("File write failed due to invalid filename.")

    filepath5 = write_results("Some string data", filename="unsafe/file.txt") # Invalid filename
    if filepath5:
        print(f"Results written to: {filepath5}")
    else:
        print("File write failed due to invalid filename.")

    filepath6 = write_results("Some string data", filename="file..txt") # Invalid filename
    if filepath6:
        print(f"Results written to: {filepath6}")
    else:
        print("File write failed due to invalid filename.")

