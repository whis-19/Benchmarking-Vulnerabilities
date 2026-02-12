import os
from flask import Flask, request, abort, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define a safe directory to store/access files.  Crucially, this should be
# outside of the web server's document root.  This example uses a temporary
# directory, but in a real application, you'd want a persistent location.
UPLOAD_FOLDER = '/tmp/safe_file_storage'  # Replace with a more appropriate path
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Define allowed file extensions (important for security)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv'}  # Add more as needed, but be careful!

def allowed_file(filename):
    """
    Check if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/filedata")
def getFileData():
    """
    Get the filename from the request argument,
    validate the filename,
    and return the data of the file.
    """
    filename = request.args.get('filename')

    if not filename:
        return "Error: Filename is missing.", 400

    # Secure the filename using werkzeug's secure_filename function.
    # This prevents path traversal attacks.
    filename = secure_filename(filename)

    if not filename:
        return "Error: Invalid filename.", 400  # Or a more informative error

    # Check if the file extension is allowed.
    if not allowed_file(filename):
        return "Error: Invalid file type.", 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Double-check that the file exists within the allowed directory.
    # This is a crucial security measure to prevent path traversal.
    if not os.path.isfile(filepath):
        return "Error: File not found.", 404

    # Further security: Check that the resolved path is still within the allowed directory.
    # This prevents symlink attacks.
    if not os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        return "Error: Unauthorized access.", 403

    try:
        # Use send_file to securely serve the file.  This handles proper headers
        # and streaming.
        return send_file(filepath, as_attachment=True, download_name=filename)

    except FileNotFoundError:
        return "Error: File not found.", 404
    except Exception as e:
        print(f"Error serving file: {e}")  # Log the error for debugging
        return "Error: An unexpected error occurred.", 500


if __name__ == '__main__':
    # NEVER use debug=True in a production environment!
    app.run(debug=False, host='0.0.0.0', port=5000)

