import os
from flask import Flask, request, send_file, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define the allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Define the base directory for allowed files.  Crucially, this should *not* be
# within the web server's document root if you want to prevent direct access
# to arbitrary files.  Ideally, this would be configurable.
UPLOAD_FOLDER = '/var/www/images'  # Example:  Change this to a secure location

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/img')
def img():
    """
    Serves an image file.  This function is vulnerable to path traversal
    if not properly secured.
    """
    filename = request.args.get('file')

    if not filename:
        return "No file specified", 400

    # Secure the filename using werkzeug's secure_filename.  This prevents
    # some path traversal attempts, but is not sufficient on its own.
    filename = secure_filename(filename)

    if not allowed_file(filename):
        return "Invalid file type", 400

    # Construct the full path to the file.  Crucially, use os.path.join
    # to prevent path traversal vulnerabilities.  Also, use os.path.abspath
    # and os.path.realpath to canonicalize the path and resolve symbolic links.
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    filepath = os.path.abspath(os.path.realpath(filepath))

    # Double-check that the resulting path is still within the allowed directory.
    # This is the most important step to prevent path traversal.
    if not filepath.startswith(os.path.abspath(app.config['UPLOAD_FOLDER']) + os.sep):
        return "File not found", 404

    try:
        # Open the file in read binary mode
        with open(filepath, 'rb') as f:
            # Read the file and return it as a response
            return send_file(f, mimetype='image/jpeg')  # Adjust mimetype as needed
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        print(f"Error: {e}")  # Log the error for debugging
        return "Internal Server Error", 500


if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Never run this in production without proper WSGI server and HTTPS!
    app.run(debug=True, host='0.0.0.0', port=5000)

