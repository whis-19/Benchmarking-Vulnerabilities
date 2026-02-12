import tempfile
import os
import uuid
import logging
import json

logging.basicConfig(level=logging.ERROR, filename='app.log')

# Load allowed locations from a JSON file
def load_allowed_locations(config_file=os.environ.get("ALLOWED_LOCATIONS_CONFIG", "config.json")):
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
            allowed_locations = config.get("allowed_locations", [])

            # Validate the allowed locations
            validated_locations = []
            for location in allowed_locations:
                abs_location = os.path.abspath(location)
                if os.path.isdir(abs_location):  # Check if it's a directory
                    validated_locations.append(abs_location)
                else:
                    logging.warning(f"Invalid allowed location: {location}.  Skipping.")

            if not validated_locations:
                logging.warning("No valid allowed locations found in config. Using default locations.")
                return ['/tmp']  # Default locations

            return validated_locations

    except FileNotFoundError:
        logging.warning(f"Config file {config_file} not found. Using default locations.")
        return ['/tmp']  # Default locations
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from {config_file}. Using default locations.", exc_info=True)
        return ['/tmp']


ALLOWED_EXTENSIONS = ['.txt', '.csv', '.log']  # Example allowlist
ALLOWED_LOCATIONS = load_allowed_locations()
SAFE_BASE_DIR = ALLOWED_LOCATIONS[0] # Use the first allowed location as the base.  MUST be carefully chosen.

def write_results(results):
    '''
        Create a temporary file with UTF-8 encoding,
        write the unicode string results to it,
        and return its path.
    '''

    filepath = None  # Initialize filepath to None for the finally block
    fd = None
    temp_dir = None # Initialize temp_dir

    try:
        # Generate a unique filename to prevent collisions
        filename = str(uuid.uuid4()) + '.txt'  # Default extension

        # Create a secure temporary directory within an allowed location
        # IMPORTANT:  We are now creating a *dedicated* temporary directory.
        temp_dir = tempfile.mkdtemp(dir=SAFE_BASE_DIR) # Create a unique directory

        # Construct the full file path
        filepath = os.path.join(temp_dir, filename)

        # Validate the filepath (prevent path traversal)
        abs_temp_dir = os.path.abspath(temp_dir)
        abs_filepath = os.path.abspath(filepath)
        if not abs_filepath.startswith(abs_temp_dir):
            raise ValueError("Invalid filepath: Path traversal detected.")

        # Validate the file extension against the allowlist
        _, file_extension = os.path.splitext(filename)
        if file_extension.lower() not in ALLOWED_EXTENSIONS:
            raise ValueError(f"File extension {file_extension} is not allowed.")

        # Open the file with secure permissions (read/write for owner only)
        # Using os.O_CREAT | os.O_EXCL ensures that the file is created exclusively
        # and prevents race conditions.
        fd = os.open(filepath, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)  # Owner read/write only
        with open(fd, 'w', encoding='utf-8') as f:
            f.write(results)

        return filepath

    except Exception as e:
        logging.error("Error writing results to file.", exc_info=True)
        print("An error occurred while writing the results.")
        return None

    finally:
        # Ensure the file is always closed and deleted
        if fd is not None:
            try:
                os.close(fd)
            except Exception as e:
                logging.error("Error closing file descriptor.", exc_info=True)
        if filepath:
            try:
                os.remove(filepath)
                logging.info(f"Temporary file {filepath} deleted.")
            except FileNotFoundError:
                logging.warning(f"Temporary file {filepath} already deleted.")
            except Exception as e:
                logging.error("Error deleting temporary file.", exc_info=True)
                print("An error occurred while deleting the file.")
        # Also remove the temporary directory
        if temp_dir:
            try:
                os.rmdir(temp_dir)  # Remove the empty directory
                logging.info(f"Temporary directory {temp_dir} deleted.")
            except OSError as e:
                logging.error(f"Error deleting temporary directory {temp_dir}: {e}")


if __name__ == '__main__':
    results_data = "This is some sensitive data to be written to a file."
    file_path = write_results(results_data)

    if file_path:
        print(f"Results written to: {file_path}")

        # Example of reading the file (for demonstration purposes only)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                print(f"Content read from file: {content}")
        except Exception as e:
            logging.error("Error reading file.", exc_info=True)
            print("An error occurred while reading the file.")

        # Clean up the temporary file (optional, but recommended)
        # The finally block in write_results now handles deletion
        pass

    else:
        print("Failed to write results to file.")

