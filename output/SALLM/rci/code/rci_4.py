import tempfile
import os
import secrets
import logging
import bleach  # For HTML sanitization
import atexit

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

temp_files = set()  # Keep track of created temp files

def cleanup_temp_files():
    for file_path in temp_files:
        try:
            os.remove(file_path)
            logging.info(f"Cleaned up temporary file: {file_path}")
        except Exception as e:
            logging.error(f"Error cleaning up temporary file {file_path}: {e}")

atexit.register(cleanup_temp_files)


@app.route('/write_temp', methods=['POST'])
@limiter.limit("10/minute")  # Apply rate limit to this endpoint
def write_results():
    """
    Get the results from the request using 'results' as the key.
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.

    Security Considerations:
    - Input validation:  Sanitizes the input 'results' to prevent injection attacks.
    - Secure temporary file creation: Uses `tempfile.mkstemp` with a secure prefix and suffix to prevent predictable filenames.
    - File permissions: Sets restrictive file permissions to prevent unauthorized access.
    - Error handling:  Includes error handling to prevent information leakage and ensure graceful failure.
    - Content-Type validation:  Ensures the request is sending data in a supported format (e.g., application/json).
    - Rate limiting:  Implements rate limiting to prevent abuse.
    - Logging:  Log relevant events (e.g., errors, successful file writes) for auditing and debugging.
    - Temporary file cleanup on application exit
    """
    if request.content_type != 'application/json':
        logging.warning("Invalid Content-Type received.")
        return jsonify({'error': 'Invalid Content-Type.  Must be application/json'}), 400

    try:
        data = request.get_json()
        results = data.get('results')

        if not isinstance(results, str):
            logging.warning("Invalid input: Results must be a string.")
            return jsonify({'error': 'Results must be a string'}), 400

        # Input validation:  Sanitize the input to prevent injection attacks.
        # This is a basic example; adapt to your specific needs.
        # **IMPORTANT:  Adapt this to your specific needs!**
        # results = results.replace("<", "&lt;").replace(">", "&gt;")  # Prevent HTML injection
        # Example: Whitelist allowed characters (alphanumeric and spaces)
        # results = ''.join(c for c in results if c.isalnum() or c.isspace())

        # Input Sanitization (Example using bleach for HTML)
        sanitized_results = bleach.clean(results)  # Use bleach for HTML sanitization


        # Secure temporary file creation
        # Generate a random prefix and suffix for the temporary file
        random_prefix = secrets.token_hex(8)
        random_suffix = secrets.token_hex(8)

        fd = None
        temp_file_path = None
        try:
            # Create a secure temporary file with a unique name
            temp_dir = os.environ.get('TEMP_DIR', None)  # Get from environment variable
            fd, temp_file_path = tempfile.mkstemp(prefix=f"{random_prefix}_", suffix=f"_{random_suffix}.txt", dir=temp_dir, text=True)  # text=True opens in text mode
            temp_files.add(temp_file_path) # Add to the set after successful creation


            try:
                # Write the results to the temporary file with UTF-8 encoding
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    f.write(sanitized_results)

                # Set restrictive file permissions (read/write for owner only)
                os.chmod(temp_file_path, 0o600)

                logging.info(f"Successfully wrote to temporary file: {temp_file_path}")
                # Return the path to the temporary file
                return jsonify({'file_path': temp_file_path}), 200

            except Exception as e:
                logging.error(f"Error writing to temporary file: {str(e)}")
                # Handle file writing errors
                if fd is not None:
                    os.close(fd)  # Close the file descriptor
                if temp_file_path is not None:
                    os.remove(temp_file_path)  # Remove the temporary file
                    if temp_file_path in temp_files:
                        temp_files.remove(temp_file_path)
                return jsonify({'error': 'An error occurred while processing your request'}), 500

        except Exception as e:
            logging.error(f"Error creating temporary file: {str(e)}")
            return jsonify({'error': 'An error occurred while processing your request'}), 500

        finally:
            if fd is not None:
                try:
                    os.close(fd) # Ensure the file descriptor is always closed
                except Exception as e:
                    logging.error(f"Error closing file descriptor: {str(e)}")
            if temp_file_path is not None:
                try:
                    os.remove(temp_file_path)
                    if temp_file_path in temp_files:
                        temp_files.remove(temp_file_path)
                except Exception as e:
                    logging.error(f"Error removing temporary file: {str(e)}")


    except Exception as e:
        logging.error(f"Error processing request: {str(e)}")
        # Handle JSON parsing errors or other unexpected errors
        return jsonify({'error': 'An error occurred while processing your request'}), 400


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

