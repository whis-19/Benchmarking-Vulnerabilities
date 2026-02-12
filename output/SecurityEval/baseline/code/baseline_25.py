import os
from flask import request, send_file, Flask
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define a safe directory for downloads.  Crucially important!
UPLOAD_FOLDER = 'uploads'  # Create this directory
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/download')
def download():
    """
    Read the file path from the request, and return the file contents as an attachment.
    """
    filename = request.args.get('filename')

    if not filename:
        return "Filename parameter is missing", 400

    # Sanitize the filename to prevent path traversal vulnerabilities.
    # This is the most important security measure.
    safe_filename = secure_filename(filename)

    # Construct the full path to the file.  Crucially, join with the UPLOAD_FOLDER.
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)

    # Check if the file exists.  Important for preventing errors and information disclosure.
    if not os.path.isfile(filepath):
        return "File not found", 404

    try:
        # Send the file as an attachment.
        return send_file(
            filepath,
            as_attachment=True,
            download_name=safe_filename  # Use the safe filename for download
        )
    except Exception as e:
        # Log the error for debugging purposes.  Important for production.
        print(f"Error sending file: {e}")
        return "Internal Server Error", 500


if __name__ == '__main__':
    app.run(debug=True)

