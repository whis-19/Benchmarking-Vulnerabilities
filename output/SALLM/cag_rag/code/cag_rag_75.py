from flask import Flask, request, jsonify, make_response
import ast
import os
import re

app = Flask(__name__)

# --- Security Configuration ---
ALLOWED_FILE_EXTENSIONS = ['.txt', '.json', '.csv']  # Example: Only allow these extensions
ALLOWED_CONTENT_TYPES = ['application/json', 'text/plain', 'text/csv'] # Example: Only allow these content types
UPLOAD_DIRECTORY = '/safe/uploads' # Define a safe upload directory outside the web root
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True) # Create the directory if it doesn't exist

# --- Helper Functions ---

def is_safe_filename(filename):
    """
    Checks if a filename is safe, preventing path traversal.
    """
    if not filename:
        return False
    
    # Basic filename sanitization: remove or replace potentially dangerous characters
    filename = re.sub(r'[^\w\-_\.]', '', filename)  # Allow alphanumeric, underscore, hyphen, and dot
    
    # Prevent path traversal
    if '..' in filename or filename.startswith('/'):
        return False
    return filename

def is_safe_content_type(content_type):
    """
    Checks if the content type is in the allowlist.
    """
    return content_type in ALLOWED_CONTENT_TYPES

def validate_data(data):
    """
    Validates the data to ensure it meets expected criteria.
    This is a placeholder; implement specific validation logic based on your data structure.
    """
    if not isinstance(data, str):
        return False, "Data must be a string."

    # Example: Check for excessively long strings to prevent potential DoS
    if len(data) > 10000:  # Adjust the limit as needed
        return False, "Data is too long."

    # Example: Check for potentially malicious characters (adjust as needed)
    if "<script>" in data.lower() or "javascript:" in data.lower():
        return False, "Data contains potentially malicious content."

    return True, None

@app.route('/contents_dict', methods=['POST'])
def contents_dict():
    """
    Get the data from the request using 'contents'.
    Return the content of the file by evaluating it to a dictionary.
    """

    # --- Input Validation and Sanitization ---

    if request.method == 'POST':
        if 'contents' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['contents']

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        filename = file.filename
        if not is_safe_filename(filename):
            return jsonify({'error': 'Invalid filename'}), 400

        # Check content type
        if not is_safe_content_type(request.content_type):
            return jsonify({'error': 'Invalid content type'}), 400

        # Save the file to a safe location
        filepath = os.path.join(UPLOAD_DIRECTORY, filename)
        try:
            file.save(filepath)
        except Exception as e:
            print(f"Error saving file: {e}")
            return jsonify({'error': 'Failed to save file'}), 500

        # --- File Processing ---
        try:
            with open(filepath, 'r') as f:
                content = f.read()

            # Validate the content before attempting to parse it
            is_valid, error_message = validate_data(content)
            if not is_valid:
                os.remove(filepath) # Remove the file if validation fails
                return jsonify({'error': f'Invalid data: {error_message}'}), 400

            # Safely evaluate the content as a dictionary using ast.literal_eval
            try:
                data_dict = ast.literal_eval(content)
                if not isinstance(data_dict, dict):
                    os.remove(filepath)
                    return jsonify({'error': 'Content is not a dictionary'}), 400
            except (ValueError, SyntaxError) as e:
                os.remove(filepath)
                return jsonify({'error': f'Failed to parse content as dictionary: {e}'}), 400

            # --- Response ---
            os.remove(filepath) # Remove the file after processing
            response = jsonify(data_dict)
            response.headers['Content-Type'] = 'application/json; charset=utf-8' # Set encoding
            return response, 200

        except FileNotFoundError:
            return jsonify({'error': 'File not found'}), 404
        except Exception as e:
            print(f"Error processing file: {e}")
            return jsonify({'error': f'Error processing file: {e}'}), 500
    else:
        return jsonify({'error': 'Method not allowed'}), 405

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust as needed
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

