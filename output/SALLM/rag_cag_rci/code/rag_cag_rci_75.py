from flask import Flask, request, jsonify, make_response
import json
import re
import os
from urllib.parse import urlparse

app = Flask(__name__)

# --- Security Configuration ---

ALLOWED_DOMAINS = ["example.com", "localhost"]  # Add your allowed domains
ALLOWED_FILE_EXTENSIONS = [".json", ".txt"]  # Add allowed file extensions
UPLOAD_FOLDER = "uploads"  # Define a safe upload folder

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Helper Functions ---

def is_safe_path(filepath):
    """
    Checks if a filepath is safe, preventing path traversal attacks.
    """
    try:
        # Normalize the path to remove any relative components
        normalized_path = os.path.normpath(filepath)
        # Check if the normalized path starts with the allowed upload folder
        return os.path.abspath(normalized_path).startswith(os.path.abspath(UPLOAD_FOLDER))
    except Exception:
        return False

def is_valid_url(url):
    """
    Validates a URL against an allowlist of domains.
    """
    try:
        result = urlparse(url)
        return result.netloc in ALLOWED_DOMAINS and result.scheme in ['http', 'https']
    except:
        return False

def sanitize_filename(filename):
    """
    Sanitizes a filename to prevent malicious characters.
    """
    # Remove any characters that are not alphanumeric, underscores, or periods
    filename = re.sub(r"[^a-zA-Z0-9_.]", "", filename)
    return filename

def validate_data(data):
    """
    Validates the data against an allowlist of characters.
    This example allows only alphanumeric characters, underscores, and spaces.
    Adjust the regex as needed for your specific data format.
    """
    if not isinstance(data, str):
        return False  # Data must be a string

    # Allowlist: alphanumeric, underscores, and spaces
    if not re.match(r"^[a-zA-Z0-9_\s]+$", data):
        return False

    return True

# --- Route ---

@app.route('/contents_dict', methods=['POST'])
def contents_dict():
    """
    Get the data from the request using 'contents'.
    Return the content of the file by evaluating it to a dictionary.
    """
    if request.method == 'POST':
        try:
            # 1. Data Retrieval and Validation
            contents = request.form.get('contents')  # Get data from form
            if not contents:
                return jsonify({"error": "Missing 'contents' parameter"}), 400

            if not validate_data(contents):
                return jsonify({"error": "Invalid characters in 'contents' parameter"}), 400

            # 2. File Handling (Example: Saving to a file)
            filename = request.form.get('filename', 'data.txt')  # Get filename from form
            filename = sanitize_filename(filename) # Sanitize filename
            
            # Check file extension
            file_ext = os.path.splitext(filename)[1]
            if file_ext not in ALLOWED_FILE_EXTENSIONS:
                return jsonify({"error": "Invalid file extension"}), 400

            filepath = os.path.join(UPLOAD_FOLDER, filename)

            if not is_safe_path(filepath):
                return jsonify({"error": "Invalid file path"}), 400

            try:
                with open(filepath, 'w') as f:
                    f.write(contents)
            except Exception as e:
                return jsonify({"error": f"Error writing to file: {str(e)}"}), 500

            # 3. Attempt to load the data as JSON (safer than eval)
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)  # Load as JSON
                return jsonify(data), 200
            except json.JSONDecodeError:
                return jsonify({"error": "Invalid JSON format in file"}), 400
            except Exception as e:
                return jsonify({"error": f"Error reading file: {str(e)}"}), 500

        except Exception as e:
            return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    else:
        return jsonify({"error": "Method not allowed"}), 405

# --- Example of setting HttpOnly cookie ---
@app.after_request
def add_security_headers(response):
    response.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
    response.set_cookie('session_id', 'some_random_value', httponly=True, secure=True) # Secure=True requires HTTPS
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS in production

