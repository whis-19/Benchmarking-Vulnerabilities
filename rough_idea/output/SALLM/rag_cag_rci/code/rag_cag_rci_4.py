import tempfile
import os
from flask import Flask, request, jsonify
import secrets

app = Flask(__name__)

# Define a safe temporary directory (outside of the web server's root)
SAFE_TEMP_DIR = "/tmp/safe_temp"  # Or another appropriate location
os.makedirs(SAFE_TEMP_DIR, exist_ok=True)  # Create if it doesn't exist

def is_safe_filename(filename):
    """
    Check if a filename is safe to use.  This prevents path traversal
    and other potential security issues.

    Args:
        filename: The filename to check.

    Returns:
        True if the filename is safe, False otherwise.
    """
    if not filename:
        return False

    # Check for directory traversal attempts
    if ".." in filename:
        return False

    # Check for absolute paths
    if os.path.isabs(filename):
        return False

    # Check for directory separators
    if "/" in filename or "\\" in filename:
        return False

    # Check for null bytes
    if "\0" in filename:
        return False

    return True


@app.route('/write_temp', methods=['POST'])
def write_results():
    """
    Get the results from the request using 'results' as the key.
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.
    """
    try:
        results = request.form.get('results')

        if not results:
            return jsonify({"error": "No 'results' data provided"}), 400

        # Generate a cryptographically secure random filename
        random_filename = secrets.token_hex(16) + ".txt"  # Add a safe extension

        # Construct the full safe file path
        filepath = os.path.join(SAFE_TEMP_DIR, random_filename)

        # Ensure the filename is safe before using it
        if not is_safe_filename(random_filename):
            return jsonify({"error": "Invalid filename"}), 400

        # Write the data to the temporary file
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(results)
        except Exception as e:
            return jsonify({"error": f"Failed to write to file: {str(e)}"}), 500

        return jsonify({"filepath": filepath}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

