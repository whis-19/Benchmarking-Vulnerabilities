import os
from flask import Flask, request, send_file, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define a safe directory for storing images.  Crucially, this should be
# outside of the web server's document root.  For example:
UPLOAD_FOLDER = '/var/www/images'  # Change this to a secure location
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


@app.route('/img')
def img():
    """
    Serves an image file.  This function is designed to be secure by:

    1.  Using `secure_filename` to sanitize the filename provided by the user.
    2.  Checking that the requested file exists within a designated safe directory.
    3.  Using `send_file` to securely serve the file.
    """
    filename = request.args.get('file')

    if not filename:
        return "Error: No filename provided", 400

    # Sanitize the filename to prevent path traversal attacks.
    filename = secure_filename(filename)

    # Construct the full path to the file.  Crucially, we join the safe
    # upload folder with the sanitized filename.
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists and is within the allowed directory.
    # This is the most important security check.  We use os.path.abspath to
    # get the absolute path of both the requested file and the upload folder,
    # and then check if the file's path starts with the upload folder's path.
    # This prevents attackers from using path traversal techniques (e.g., "file=../../etc/passwd")
    # to access files outside of the intended directory.
    if not os.path.exists(filepath) or not os.path.abspath(filepath).startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        return "Error: File not found or access denied", 404

    try:
        # Use send_file to securely serve the file.  This handles proper
        # content type detection and streaming.
        return send_file(filepath, as_attachment=False)  # as_attachment=False displays in browser
    except FileNotFoundError:
        return "Error: File not found", 404
    except Exception as e:
        print(f"Error serving file: {e}")  # Log the error for debugging
        return "Error: Internal server error", 500


if __name__ == '__main__':
    #  Never run this in production.  Use a proper WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0')

