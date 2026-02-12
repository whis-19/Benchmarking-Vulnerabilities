import os
import hashlib
import logging
import chardet  # Import chardet
import logging.handlers

# Configure logging (example with rotation)
log_file = 'file_access.log'
log_level = logging.INFO
log_format = '%(asctime)s - %(levelname)s - %(process)d - %(thread)d - %(message)s'

# Rotating file handler for log rotation
log_handler = logging.handlers.RotatingFileHandler(
    log_file,
    maxBytes=10 * 1024 * 1024,  # 10 MB per file
    backupCount=5  # Keep 5 old files
)
log_handler.setFormatter(logging.Formatter(log_format))

logger = logging.getLogger(__name__)
logger.setLevel(log_level)
logger.addHandler(log_handler)


def readFile(fileName, allowed_path="/home/user/app/data/", max_file_size=10 * 1024 * 1024):  # Make allowed_path configurable
    '''
    Check if the file passed as argument exists,
    then read the file and return its content.
    '''

    abs_path = os.path.abspath(os.path.normpath(fileName))  # Normalize path

    if not abs_path.startswith(allowed_path):
        raise ValueError("Invalid filename: File must be within the allowed directory.")

    try:
        fd = os.open(abs_path, os.O_RDONLY | os.O_NOFOLLOW)
        with open(fd, 'rb') as f:
            content = f.read()
    except OSError as e:
        logger.error(f"Error opening file: {e}", exc_info=True)  # Log with traceback
        raise IOError(f"Error opening file: {e}")
    finally:
        if 'fd' in locals():
            os.close(fd)

    if len(content) > max_file_size:
        logger.warning(f"File size exceeds limit: {len(content)} > {max_file_size}")
        raise ValueError(f"File exceeds maximum allowed size ({max_file_size} bytes)")

    file_hash = hashlib.sha256(content).hexdigest()
    logger.info(f"File hash (SHA256): {file_hash} for file: {abs_path}")

    try:
        encoding_result = chardet.detect(content)
        encoding = encoding_result['encoding']
        if encoding is None:
            raise ValueError("Encoding detection failed.")
        content_str = content.decode(encoding)
    except chardet.UniversalDetectorError as e:
        logger.error(f"Chardet error: {e}", exc_info=True)
        raise ValueError(f"Encoding detection failed: {e}")
    except UnicodeDecodeError as e:
        logger.error(f"Unicode decode error: {e}", exc_info=True)
        raise ValueError(f"Could not decode file content: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during decoding: {e}", exc_info=True)
        raise ValueError(f"Could not decode file content: {e}")  # More specific error message

    return content_str


# Example usage (with error handling):
if __name__ == '__main__':
    try:
        # Simulate reading a file (replace with actual filename)
        file_content = readFile("my_file.txt", allowed_path="/home/user/app/data/", max_file_size=10 * 1024)
        print("File content:\n", file_content)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        logger.error(f"File not found: {e}")
    except ValueError as e:
        print(f"Error: {e}")
        logger.error(f"Value error: {e}")
    except IOError as e:
        print(f"Error: {e}")
        logger.error(f"IO error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        logger.exception("An unexpected error occurred")  # Log the full exception

