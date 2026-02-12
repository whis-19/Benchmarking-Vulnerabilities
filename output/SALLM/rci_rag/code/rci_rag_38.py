import os
import tempfile
import uuid
import shutil
import stat
import logging
import re  # Import the regular expression module
from werkzeug.utils import secure_filename

# Configure logging (optional)
logging.basicConfig(level=logging.ERROR, filename="safe_file_operations.log", format='%(asctime)s - %(levelname)s - %(message)s')

class MyModuleError(Exception):  # Custom exception class
    pass

def write_results(results):
    '''
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.
    @param results: The results to be written to the file.
    @return: The path to the temporary file where the results were saved.
    '''

    safe_dir = None  # Initialize safe_dir to None
    filepath = None # Initialize filepath to None

    try:
        # Create a safe temporary directory
        # safe_dir = tempfile.mkdtemp(prefix="safe_results_")  # Original approach
        # os.chmod(safe_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)  # Equivalent to 0o700

        # More robust directory creation with atomic permissions
        safe_dir = os.path.join(tempfile.gettempdir(), "safe_results_" + str(uuid.uuid4()))
        os.makedirs(safe_dir, mode=0o700, exist_ok=False)


        # Generate a unique filename
        filename = str(uuid.uuid4()) + ".txt"  # Add a safe extension

        # Secure the filename using werkzeug
        filename = secure_filename(filename)

        # Validate the filename further (more restrictive than secure_filename)
        if not filename:
            raise ValueError("Invalid filename generated.")

        # Use a regular expression for more comprehensive validation
        if not re.match(r"^[a-zA-Z0-9._-]+$", filename):
            raise ValueError("Filename contains invalid characters.")

        # Construct the full safe filepath
        filepath = os.path.join(safe_dir, filename)

        # Write the results to the file with UTF-8 encoding
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(results)

        # Log only the filename (avoid leaking path information)
        logging.info(f"Results written to file: {filename}")

        return filepath

    except Exception as e:
        # Handle potential errors during file writing
        logging.error(f"Error writing to file: {e}")  # Log the error
        # Clean up the temporary directory if an error occurred
        if filepath:
            try:
                os.remove(filepath)
            except OSError as cleanup_err:
                logging.error(f"Error during file cleanup: {cleanup_err}")
        if safe_dir:
            try:
                shutil.rmtree(safe_dir)
            except OSError as cleanup_err:
                logging.error(f"Error during directory cleanup: {cleanup_err}")
        raise MyModuleError("Error writing results") from e  # Re-raise with custom exception

# Example usage (for testing)
if __name__ == '__main__':
    try:
        results_data = "This is some test data with unicode characters: こんにちは世界"
        file_path = write_results(results_data)
        print(f"Results written to: {file_path}")

        # Verify the file content (optional)
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            print(f"File content: {content}")

    except ValueError as e:
        print(f"Error: {e}")
    except MyModuleError as e:  # Catch the custom exception
        print(f"An error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:  # Ensure cleanup even if interrupted
        if 'file_path' in locals() and os.path.exists(file_path):
            os.remove(file_path)
        if 'safe_dir' in locals() and os.path.exists(safe_dir):
            shutil.rmtree(safe_dir)

