import logging
import re

# Configure logging (replace with your actual logging setup)
logging.basicConfig(level=logging.INFO)

def validate_file_content_type(file, allowed_mime_types):
    """Validates the file content type using libmagic."""

    try:
        import magic  # Import here to handle ImportError
    except ImportError:
        raise ValueError("The 'python-magic' library is not installed.  Please install it to enable file content validation.")

    # Validate allowed_mime_types (example)
    if not isinstance(allowed_mime_types, list):
        raise ValueError("allowed_mime_types must be a list.")
    for mime_type in allowed_mime_types:
        if not isinstance(mime_type, str) or not re.match(r"^[a-z]+/[a-z0-9\-\+\.]+$", mime_type): # More robust regex needed for production
            raise ValueError(f"Invalid MIME type in allowed_mime_types: {mime_type}")

    # Whitelist of allowed MIME types (for extra security)
    valid_mime_types = ["image/jpeg", "image/png", "text/plain"] # Add more as needed
    if not all(mime_type in valid_mime_types for mime_type in allowed_mime_types):
        raise ValueError("allowed_mime_types contains an invalid or disallowed MIME type.")


    try:
        # Read a larger chunk, but limit the total file size elsewhere
        file_content = file.read(4096)
        mime = magic.from_buffer(file_content, mime=True)
        file.seek(0)  # Rewind the file

        if mime not in allowed_mime_types:
            raise ValueError(f"Invalid file content type: {mime}")

        # Example: If it's an image, try to decode it (defense in depth)
        if mime in ["image/jpeg", "image/png"]:
            try:
                from PIL import Image  # Requires Pillow library
                Image.open(file).verify() # Verify image integrity
                file.seek(0) # Rewind after verification
            except Exception as e:
                logging.warning(f"Image verification failed: {e}")
                raise ValueError("Invalid image file.")

    except magic.MagicException as e:
        logging.exception("Error determining file type (libmagic):") # Log the full exception
        raise ValueError("Error determining file type.") # Generic error for the user
    except IOError as e:
        logging.exception("IOError during file content validation:")
        raise ValueError("Error reading file.")
    except Exception as e:
        logging.exception("Unexpected error during file content validation:")
        raise ValueError("Error during file content validation.")
    finally:
        # Ensure the file is closed (if applicable)
        if hasattr(file, 'close') and callable(getattr(file, 'close')):
            try:
                file.close()
            except Exception:
                logging.exception("Error closing file:") # Log if closing fails


# Example usage (with validation of allowed_mime_types)
allowed_types = ["image/jpeg", "image/png", "text/plain"]
# Example file (replace with your actual file object)
# with open("test.jpg", "rb") as f:
#     try:
#         validate_file_content_type(f, allowed_types)
#         print("File type is valid.")
#     except ValueError as e:
#         print(f"File type validation failed: {e}")

