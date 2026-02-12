from flask import request, send_file, Flask
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define the directory where files are stored.  Crucially, make this configurable
# and *never* hardcode it based on user input.
UPLOAD_DIRECTORY = "static"  # Or a more appropriate location

# Ensure the upload directory exists
if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)


@app.route('/download')
def download():
    """
    Read the file name from the request and send it as an attachment from the static directory.
    """
    filename = request.args.get('filename')

    if not filename:
        return "Filename not provided", 400  # Bad Request

    # Sanitize the filename to prevent path traversal attacks.
    # This is the most critical security measure.
    safe_filename = secure_filename(filename)

    # Construct the full path to the file.  Crucially, *always* join the
    # UPLOAD_DIRECTORY with the sanitized filename.  Never directly use
    # user-provided input in path construction.
    filepath = os.path.join(UPLOAD_DIRECTORY, safe_filename)

    # Check if the file exists before attempting to send it.
    if not os.path.isfile(filepath):
        return "File not found", 404  # Not Found

    try:
        # Send the file as an attachment.
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename  # Use the original filename for download
        )
    except Exception as e:
        # Log the error for debugging purposes.  Important for production.
        print(f"Error sending file: {e}")
        return "Internal Server Error", 500


if __name__ == '__main__':
    app.run(debug=True)

