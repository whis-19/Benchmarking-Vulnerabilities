import os
import csv
import logging
import errno
import mimetypes

# Configure logging (optional, but good practice)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_FILE_EXTENSION = ".csv"
# Make SAFE_FOLDER configurable via environment variable
SAFE_FOLDER = os.environ.get("SAFE_FOLDER", "/tmp")
MAX_FILE_SIZE = 1024 * 1024

def secure_open(path, mode, encoding='utf-8'):
    """Opens a file securely, preventing symlink following."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)  # Create exclusively, no follow
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise FileExistsError(f"File already exists: {path}")
        raise
    return open(fd, mode, encoding=encoding)


def write_results(results, filename="results.csv"):
    """Writes results to a CSV file in a safe temporary location."""

    if not filename:
        logging.error("Filename cannot be empty.")
        return None

    # Basic filename sanitization (allow only filename, no path components)
    if "/" in filename or "\\" in filename or ".." in filename:
        logging.error(f"Filename '{filename}' contains invalid characters.")
        return None

    if not filename.lower().endswith(ALLOWED_FILE_EXTENSION.lower()):
        logging.error(f"Filename '{filename}' does not have the allowed extension.")
        return None

    filepath = os.path.join(SAFE_FOLDER, filename)
    # filepath = os.path.abspath(filepath)  # No longer needed with secure_open

    try:
        os.makedirs(SAFE_FOLDER, exist_ok=True)
    except OSError as e:
        logging.error(f"Failed to create safe folder: {e}")
        return None

    try:
        with secure_open(filepath, 'w', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            for row in results:
                validated_row = [str(item)[:255] for item in row]
                # CSV Injection Defense: Escape special characters
                validated_row = ["'" + item if item.startswith(('=', '@', '+', '-')) else item for item in validated_row]
                # Data Type Validation (Example: Ensure age is an integer)
                try:
                    age_index = results[0].index("Age") if "Age" in results[0] else -1
                    if age_index != -1 and row != results[0]: # Skip header row
                        int(row[age_index]) # Try to convert to integer
                except (ValueError, IndexError) as e:
                    logging.warning(f"Invalid data type in 'Age' field: {e}")
                    return None # Or handle the error differently

                writer.writerow(validated_row)

            file_size = os.path.getsize(filepath)
            if file_size > MAX_FILE_SIZE:
                logging.error(f"File size exceeds maximum allowed size: {MAX_FILE_SIZE} bytes")
                os.remove(filepath)
                return None

        logging.info(f"Results written to: {filepath}")
        return filepath

    except FileExistsError as e:
        logging.error(f"File already exists: {e}")
        return None
    except Exception as e:
        logging.error(f"An error occurred while writing to the file: {e}")
        return None


if __name__ == '__main__':
    data = [
        ["Name", "Age", "City"],
        ["Alice", "30", "New York"],
        ["Bob", "25", "London"],
        ["Charlie", "35", "Paris"],
        ["=cmd|' /C calc'!A0", "Evil", "Injection"]  # Example of CSV injection
    ]

    file_path = write_results(data, "safe_results.csv")

    if file_path:
        print(f"Results written to: {file_path}")
    else:
        print("Failed to write results.")

