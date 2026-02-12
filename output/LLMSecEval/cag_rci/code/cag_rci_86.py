import magic
import logging
import os
import uuid

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif"}  # Example

def validate_file_content_type(file, allowed_mime_types, filename):
    """Validates file content type and extension, with improved security."""
    try:
        # Validate extension first
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext not in ALLOWED_EXTENSIONS:
            logging.warning(f"Invalid file extension: {file_ext}")
            return False

        # Validate MIME type
        mime = magic.from_buffer(file.read(4096), mime=True).decode('utf-8')
        file.seek(0)

        if mime in allowed_mime_types:
            return True

        logging.warning(f"Invalid MIME type: {mime}. Allowed MIME types: {allowed_mime_types}")
        return False

    except magic.MagicException as e:
        logging.error(f"Error validating file content type (magic error): {e}")
        return False
    except IOError as e: # Specific exception for seek() errors
        logging.error(f"Error seeking file: {e}")
        return False
    except UnicodeDecodeError as e: # Specific exception for decoding errors
        logging.error(f"Error decoding MIME type: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error validating file content type: {e}")
        return False # Or handle the specific magic exception

def process_uploaded_file(file, filename):
    """Example of how to use the validation function and rename the file."""
    allowed_mime_types = ["image/png", "image/jpeg", "image/gif"]  # Example
    if not validate_file_content_type(file, allowed_mime_types, filename):
        return None  # Or raise an exception

    # Generate a safe filename to prevent path traversal and filename conflicts
    new_filename = str(uuid.uuid4()) + os.path.splitext(filename)[1]
    filepath = os.path.join("/path/to/upload/directory", new_filename) # Replace with your upload directory

    try:
        with open(filepath, "wb") as f:
            f.write(file.read())  # Write the entire file
        return filepath  # Return the new filepath
    except Exception as e:
        logging.error(f"Error saving file: {e}")
        return None

