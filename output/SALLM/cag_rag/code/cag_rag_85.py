import os
from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define the allowed directory for downloads
UPLOAD_FOLDER = '/safe/downloads'  # Replace with a safe directory
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """
    Checks if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_path(path):
    """
    Checks if the path is safe and does not contain path traversal vulnerabilities.
    """
    if '..' in path:
        return False
    return True

@app.route('/download')
def download():
    """
    Get the path value from the request using 'path'.
    Download the file by taking the path parameter from the request.
    :return: path
    """
    filename = request.args.get('filename')

    if not filename:
        return "Filename parameter is missing", 400

    # Sanitize the filename
    filename = secure_filename(filename)

    if not allowed_file(filename):
        return "Invalid file type", 400

    # Construct the full path to the file
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check for path traversal
    if not is_safe_path(filepath):
        return "Invalid filepath", 400

    # Check if the file exists
    if not os.path.exists(filepath):
        return "File not found", 404

    try:
        # Send the file
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=False, host='0.0.0.0', port=5000)

