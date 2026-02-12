from flask import Flask, request, abort
import os
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv'}

# Define the safe folder where files can be opened
SAFE_FOLDER = 'safe_files'  # Create this folder in your project directory

# Create the safe folder if it doesn't exist
if not os.path.exists(SAFE_FOLDER):
    os.makedirs(SAFE_FOLDER)


def allowed_file(filename):
    """
    Check if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/open_file')
def open_file():
    """
    Get the file name from the request using 'file_name' and check if the file opens successfully
    in the SAFE_FOLDER.

    :return: The file object if the file opens successfully, None otherwise.
    """
    filename = request.args.get('file_name')

    if not filename:
        logging.warning("No filename provided.")
        return "No filename provided", 400

    # Validate filename using secure_filename
    filename = secure_filename(filename)

    if not filename:
        logging.warning("Filename contains invalid characters.")
        return "Invalid filename", 400

    # Check for multiple dots
    if filename.count('.') > 1:
        logging.warning("Filename contains multiple dots.")
        return "Invalid filename: Multiple dots", 400

    # Check for directory separators
    if '/' in filename or '\\' in filename:
        logging.warning("Filename contains directory separators.")
        return "Invalid filename: Directory separators not allowed", 400

    # Check if the file extension is allowed
    if not allowed_file(filename):
        logging.warning(f"File extension not allowed: {filename}")
        return "Invalid file type", 400

    # Construct the full file path within the safe folder
    filepath = os.path.join(SAFE_FOLDER, filename)

    # Canonicalize the path to remove ".." sequences and symbolic links
    filepath = os.path.realpath(filepath)

    # Ensure the path is still within the safe folder after canonicalization
    if not filepath.startswith(os.path.realpath(SAFE_FOLDER) + os.sep):
        logging.warning(f"Attempt to access file outside of safe folder: {filepath}")
        return "Access denied: File is outside the allowed directory", 403

    try:
        # Open the file in read mode
        f = open(filepath, 'r')
        logging.info(f"Successfully opened file: {filepath}")
        file_content = f.read()  # Read the content for demonstration.  Remove if not needed.
        return f"File opened successfully. Content: {file_content}" # Return the content for demonstration.  Remove if not needed.

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return "File not found", 404
    except Exception as e:
        logging.exception(f"Error opening file: {filepath}")
        return f"Error opening file: {str(e)}", 500
    finally:
        if 'f' in locals() and f:
            f.close()
            logging.info(f"File closed: {filepath}")


if __name__ == '__main__':
    app.run(debug=True)

