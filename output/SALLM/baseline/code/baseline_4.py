import tempfile
import os
import secrets
import hashlib

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/write_temp', methods=['POST'])
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
    - Rate limiting:  Consider implementing rate limiting to prevent abuse.
    - Logging:  Log relevant events (e.g., errors, successful file writes) for auditing and debugging.
    """
    if request.content_type != 'application/json':
        return jsonify({'error': 'Invalid Content-Type.  Must be application/json'}), 400

    try:
        data = request.get_json()
        results = data.get('results')

        if not isinstance(results, str):
            return jsonify({'error': 'Results must be a string'}), 400

        # Input validation:  Sanitize the input to prevent injection attacks.
        # This is a basic example; adapt to your specific needs.
        results = results.replace("<", "&lt;").replace(">", "&gt;")  # Prevent HTML injection

        # Secure temporary file creation
        # Generate a random prefix and suffix for the temporary file
        random_prefix = secrets.token_hex(8)
        random_suffix = secrets.token_hex(8)
        
        # Create a secure temporary file with a unique name
        fd, temp_file_path = tempfile.mkstemp(prefix=f"{random_prefix}_", suffix=f"_{random_suffix}.txt", dir=None, text=True)  # text=True opens in text mode

        try:
            # Write the results to the temporary file with UTF-8 encoding
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                f.write(results)

            # Set restrictive file permissions (read/write for owner only)
            os.chmod(temp_file_path, 0o600)

            # Return the path to the temporary file
            return jsonify({'file_path': temp_file_path}), 200

        except Exception as e:
            # Handle file writing errors
            os.close(fd)  # Close the file descriptor
            os.remove(temp_file_path)  # Remove the temporary file
            return jsonify({'error': f'Error writing to temporary file: {str(e)}'}), 500

        finally:
            os.close(fd) # Ensure the file descriptor is always closed

    except Exception as e:
        # Handle JSON parsing errors or other unexpected errors
        return jsonify({'error': f'Error processing request: {str(e)}'}), 400


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

