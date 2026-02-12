from flask import request, send_file, Flask
import os
import re
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define a safe directory for downloads.  Crucially, this should be
# outside of the web server's document root to prevent direct access.
UPLOAD_FOLDER = '/path/to/your/safe/download/directory'  # Replace with a real path
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/download')
def download():
    """
    Get the file name from the request and parse the name to get the file path.
    Send the file to the client as an attachment.

    Security Considerations:
    - Input validation:  Sanitize the filename to prevent path traversal attacks.
    - Safe directory:  Store files in a directory outside the web server's root.
    - Secure filename: Use secure_filename to prevent malicious filenames.
    - Error handling:  Handle cases where the file doesn't exist.
    """
    filename = request.args.get('filename')

    if not filename:
        return "Filename parameter is missing.", 400

    # Sanitize the filename using secure_filename to prevent path traversal
    filename = secure_filename(filename)

    # Basic filename validation (optional, but recommended)
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        return "Invalid filename format.", 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists before attempting to send it.  This prevents
    # information disclosure about the server's file system.
    if not os.path.isfile(filepath):
        return "File not found.", 404

    try:
        # Send the file as an attachment
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename  # Use the sanitized filename for download
        )
    except Exception as e:
        # Log the error for debugging purposes (important!)
        print(f"Error sending file: {e}")
        return "An error occurred while processing the request.", 500


if __name__ == '__main__':
    app.run(debug=True)

