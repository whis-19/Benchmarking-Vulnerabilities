import tempfile
import os
import uuid
import logging
import shutil
import stat
import time

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.ERROR, filename="error.log")

def rmtree_with_retry(path, retries=3, delay=0.1):
    for i in range(retries):
        try:
            shutil.rmtree(path)
            return  # Success
        except Exception as e:
            logging.warning(f"Attempt {i+1} to remove {path} failed: {e}")
            if i == retries - 1:
                raise  # Re-raise the exception after the last attempt
            time.sleep(delay)


def write_results(results, max_file_size=1024 * 1024):  # 1MB limit - Prevents excessive disk usage and potential DoS
    '''
        Create a temporary file with UTF-8 encoding,
        write the unicode string results to it,
        and return its path.
    '''

    if not isinstance(results, str):
        raise TypeError("Results must be a string.")

    if len(results) > max_file_size:
        raise ValueError(f"Results size exceeds maximum allowed size of {max_file_size} bytes.")

    safe_dir = None  # Initialize safe_dir
    try:
        # Create a temporary directory within a safe location
        safe_dir = tempfile.mkdtemp(prefix="safe_results_", dir=tempfile.gettempdir())

        # **SECURE PERMISSIONS IMMEDIATELY AFTER CREATION**
        os.chmod(safe_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)  # 0700

        # Generate a unique filename
        filename = str(uuid.uuid4()) + ".txt"  # Add extension for clarity
        filepath = os.path.join(safe_dir, filename)

        # Open the file in a secure manner
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(results)
            os.sync(f.fileno()) # Ensure data is written to disk

        return filepath

    except Exception as e:
        # Handle potential errors, such as disk space issues
        logging.error(f"Error writing results to file. Results length: {len(results)}, First 10 chars: {results[:10] if len(results) > 10 else results}")  # Log the full exception
        print("An error occurred while writing results to file.  See error logs for details.") # Generic message
        raise

    finally:
        # Ensure cleanup even if errors occur
        if safe_dir:
            try:
                rmtree_with_retry(safe_dir)
            except Exception as cleanup_error:
                logging.error(f"Error cleaning up temporary directory after retries: {cleanup_error}")
                # Consider whether to re-raise or just log the error

