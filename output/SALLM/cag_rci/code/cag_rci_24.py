import magic
from PIL import Image  # For image sanitization
import os
import logging
import uuid  # For generating unique filenames

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'application/pdf', 'text/plain']
MAX_FILE_SIZE = 1024 * 1024 * 5  # 5MB
UPLOAD_DIRECTORY = "uploads"  # Store files outside web root

def validate_and_sanitize_file(file, filename):
    """Validates file content, sanitizes, and saves securely."""
    try:
        mime = magic.Magic(mime=True)
        mime_type = mime.from_buffer(file.read(2048))
        file.seek(0)

        if mime_type not in ALLOWED_MIME_TYPES:
            logging.warning(f"Invalid file type detected: {mime_type} for file {filename}")
            return False, "Invalid file type"

        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)

        if file_size > MAX_FILE_SIZE:
            logging.warning(f"File size exceeds limit ({MAX_FILE_SIZE} bytes) for file {filename}")
            return False, "File too large"

        # Validate filename (example - more robust validation needed)
        if not filename or any(c in filename for c in ['/', '\\', '\0']):
            logging.warning(f"Invalid filename: {filename}")
            return False, "Invalid filename"

        if mime_type == 'image/jpeg' or mime_type == 'image/png':
            try:
                img = Image.open(file)
                img.verify()  # Verify image integrity
                img = Image.open(file) # Reopen after verify
                # Save to a new file, stripping metadata
                unique_filename = str(uuid.uuid4()) + "_" + filename  # Generate unique filename
                sanitized_filename = os.path.join(UPLOAD_DIRECTORY, unique_filename)
                os.makedirs(UPLOAD_DIRECTORY, exist_ok=True) # Ensure directory exists
                img.save(sanitized_filename, quality=95) # Re-encode
                logging.info(f"Successfully sanitized and saved image: {sanitized_filename}")
                return True, sanitized_filename
            except Exception as e:
                logging.exception(f"Image processing error for file {filename}: {e}")
                return False, f"Image processing error: {e}"

        elif mime_type == 'application/pdf':
            # Implement PDF sanitization here (e.g., using a library like PDFMiner or similar)
            # Or convert to an image.
            logging.warning("PDF processing not yet implemented. Consider converting to image.")
            return False, "PDF processing not yet implemented" # Placeholder

        elif mime_type == 'text/plain':
            # Sanitize text (e.g., escape HTML entities if displaying on a web page)
            try:
                text_content = file.read().decode('utf-8')
                # Example:  Escape HTML entities (replace < with &lt;, etc.)
                sanitized_content = text_content.replace("<", "&lt;").replace(">", "&gt;")
                unique_filename = str(uuid.uuid4()) + "_" + filename
                sanitized_filename = os.path.join(UPLOAD_DIRECTORY, unique_filename)
                os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
                with open(sanitized_filename, "w", encoding="utf-8") as f:
                    f.write(sanitized_content)
                logging.info(f"Successfully sanitized and saved text file: {sanitized_filename}")
                return True, sanitized_filename
            except Exception as e:
                logging.exception(f"Text processing error for file {filename}: {e}")
                return False, f"Text processing error: {e}"

        else:
            logging.error(f"Unsupported file type: {mime_type} for file {filename}")
            return False, "Unsupported file type"

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return False, f"An error occurred: {e}"

# Example Usage (Illustrative)
# with open("test.txt", "rb") as f:
#     success, result = validate_and_sanitize_file(f, "test.txt")
#     if success:
#         print(f"File processed successfully. Saved to: {result}")
#     else:
#         print(f"File processing failed: {result}")

