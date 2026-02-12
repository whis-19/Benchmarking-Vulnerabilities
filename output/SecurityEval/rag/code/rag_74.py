from flask import Flask, request, redirect, send_from_directory, abort
import os
import uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Ensure the upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Set HttpOnly flag for session cookie (if you're using sessions)
# Example:
# app.config['SESSION_COOKIE_HTTPONLY'] = True


ALLOWED_EXTENSIONS = {'pdf'}  # Allowlist for file extensions

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_path(basedir, path):
    """
    Checks if the path is safe and within the basedir.
    """
    abs_path = os.path.abspath(os.path.join(basedir, path))
    return basedir == os.path.commonpath((basedir, abs_path))


@app.route('/pdf/upload', methods=['POST'])
def upload_pdf():
    """
    Get PDF file from request, save it to ./uploads directory, and redirect to /pdf/view
    """
    if 'pdf_file' not in request.files:
        return "No file part", 400

    file = request.files['pdf_file']

    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Sanitize filename
        if not filename:
            return "Invalid filename", 400

        # Generate a unique filename to prevent collisions and potential exploits
        unique_filename = str(uuid.uuid4()) + "_" + filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        # Check for path traversal vulnerabilities
        if not is_safe_path(app.config['UPLOAD_FOLDER'], unique_filename):
            return "Invalid file path", 400

        try:
            file.save(filepath)
        except Exception as e:
            print(f"Error saving file: {e}")
            return "Error saving file", 500

        return redirect('/pdf/view?filename=' + unique_filename) # Pass the unique filename

    return "Invalid file type", 400


@app.route('/pdf/view')
def view_pdf():
    """
    View the uploaded PDF.  Requires the filename as a query parameter.
    """
    filename = request.args.get('filename')

    if not filename:
        return "Filename missing", 400

    # Sanitize the filename (important!)
    filename = secure_filename(filename)
    if not filename:
        return "Invalid filename", 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check for path traversal vulnerabilities AGAIN before serving the file
    if not is_safe_path(app.config['UPLOAD_FOLDER'], filename):
        return "Invalid file path", 400

    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        return "File not found", 404


@app.errorhandler(413)
def request_entity_too_large(error):
    return 'File Too Large', 413


if __name__ == '__main__':
    app.run(debug=True)

