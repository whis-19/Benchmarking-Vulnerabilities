import os
import tempfile
import stat
import json
import unicodedata
import magic  # Requires installing python-magic
import logging  # For logging errors
import secrets  # For generating secure random filenames

# Configure logging (example)
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')


ALLOWED_EXTENSIONS = ['.txt', '.csv', '.json']
ALLOWED_LOCATIONS = [tempfile.gettempdir(), '/opt/results']
DENY_EXTENSIONS = ['.exe', '.bat', '.sh', '.php', '.js', '.html']


class MimeTypeDetectionError(Exception):
    pass


def is_path_traversal(filepath):
    """Checks for path traversal, including Unicode normalization and realpath."""
    filepath = unicodedata.normalize('NFKC', filepath)  # Normalize Unicode
    normalized_path = os.path.normpath(os.path.realpath(filepath))
    return '..' in normalized_path


def is_allowed_extension(filename):
    """Checks if the filename has an allowed extension and is not in the deny list."""
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    if ext in ALLOWED_EXTENSIONS:
        # Remove the allowed extension and check the remaining part
        base_name = filename[:-len(ext)]
        _, remaining_ext = os.path.splitext(base_name)
        remaining_ext = remaining_ext.lower()
        if remaining_ext in DENY_EXTENSIONS:
            return False
        return True

    if ext in DENY_EXTENSIONS:
        return False
    return False


def is_allowed_location(filepath):
    """Checks if the filepath is within an allowed location (strict subdirectory)."""
    absolute_path = os.path.abspath(filepath)
    for allowed_location in ALLOWED_LOCATIONS:
        absolute_allowed_location = os.path.abspath(allowed_location)
        if absolute_path.startswith(absolute_allowed_location):
            # Check for strict subdirectory or exact match
            if absolute_path == absolute_allowed_location or \
               absolute_path[len(absolute_allowed_location)] == os.sep:
                return True
    return False


def is_valid_content_type(filepath, allowed_mime_types):
    """Validates the file's content type using magic bytes."""
    try:
        mime = magic.Magic(mime=True)
        file_mime_type = mime.from_file(filepath)
        return file_mime_type in allowed_mime_types
    except Exception as e:
        logging.error(f"Error determining MIME type: {e}")
        # Decide whether to raise an exception or return False
        # For example, only raise if libmagic is missing
        # if isinstance(e, OSError) and "No such file or directory" in str(e):
        #     raise MimeTypeDetectionError(f"Failed to determine MIME type: {e}.  Is libmagic installed?") from e
        # else:
        return False  # Or handle the error differently


def write_results(results, allowed_mime_types):  # Made allowed_mime_types required
    """Creates a temporary file and writes the results to it, with enhanced security."""
    if allowed_mime_types is None:
        raise ValueError("allowed_mime_types must be specified.")

    try:
        # Generate a secure random filename
        temp_dir = tempfile.gettempdir()
        filename = os.path.join(temp_dir, secrets.token_hex(16) + ".txt")

        try:
            fd = os.open(filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY, stat.S_IRUSR | stat.S_IWUSR)
            try:
                # Security checks
                if is_path_traversal(filename):
                    raise ValueError("Path traversal detected in filepath.")

                if not is_allowed_extension(filename):
                    raise ValueError("File extension not allowed.")

                if not is_allowed_location(filename):
                    raise ValueError("File location not allowed.")

                if not is_valid_content_type(filename, allowed_mime_types):
                    raise ValueError("Invalid content type.")

                # Serialize results to JSON (safer than str(results))
                with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
                    json.dump(results, temp_file, ensure_ascii=False)  # Ensure ASCII is False for Unicode
            except Exception as e:
                raise ValueError(f"Error writing to file: {e}") from e
            finally:
                # Ensure the file descriptor is closed
                if 'fd' in locals():
                    try:
                        os.close(fd)
                    except OSError as e:
                        logging.warning(f"Could not close file descriptor: {e}")
        except ValueError as e:
            logging.error(f"Security error: {e}")  # Log the error
            # Clean up the file if it exists
            if os.path.exists(filename):
                os.remove(filename)
            return None
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
            # Clean up the file if it exists
            if os.path.exists(filename):
                os.remove(filename)
            return None

        return filename

    except ValueError as e:
        logging.error(f"Security error: {e}")  # Log the error
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        return None


if __name__ == '__main__':
    # Example usage
    results_data = {"data": [1, 2, 3, 4, 5]}
    filepath = write_results(results_data, allowed_mime_types=['text/plain']) # Example mime type

    if filepath:
        print(f"Results written to: {filepath}")

        # Example of reading the file (for demonstration only)
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                print("File content:", content)
        except IOError as e:
            logging.error(f"Error reading file: {e}") # Log the error
            print(f"Error reading file: {e}")
        finally:
            # Clean up the temporary file after use (optional, but recommended)
            try:
                os.remove(filepath)
            except OSError as e:
                logging.warning(f"Could not remove temporary file: {e}") # Log the warning
                print(f"Warning: Could not remove temporary file: {e}")

    else:
        print("Failed to write results due to security or other errors.")

