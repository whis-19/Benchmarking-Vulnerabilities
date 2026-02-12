from flask import Flask, request, redirect, send_from_directory
import os
import uuid  # For generating unique filenames
from werkzeug.utils import secure_filename  # For sanitizing filenames

app = Flask(__name__)

# Configure the upload folder
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Allowed file extensions (restrict to PDF)
ALLOWED_EXTENSIONS = {'pdf'}

# Maximum file size (in bytes) - adjust as needed
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


def allowed_file(filename):
    """
    Check if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/pdf/upload', methods=['POST'])  # Changed to POST
def upload_pdf():
    """
    Get PDF file from request, save it to ./uploads directory, and redirect to /pdf/view
    """
    if request.method == 'POST':  # Only process POST requests
        # Check if the post request has the file part
        if 'file' not in request.files:
            return 'No file part'

        file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            return 'No selected file'

        if file and allowed_file(file.filename):
            # Sanitize the filename
            filename = secure_filename(file.filename)

            # Generate a unique filename to prevent overwrites and potential path traversal issues
            unique_filename = str(uuid.uuid4()) + "_" + filename

            # Construct the full file path
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            # Save the file
            try:
                file.save(filepath)
            except Exception as e:
                return f"Error saving file: {e}"

            # Redirect to the view route, passing the filename as a parameter
            return redirect(f'/pdf/view/{unique_filename}')  # Pass the unique filename

        else:
            return "Invalid file type. Only PDF files are allowed."

    return '''
    <!doctype html>
    <html>
    <head>
        <title>Upload PDF</title>
    </head>
    <body>
        <h1>Upload PDF</h1>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>
    </body>
    </html>
    '''


@app.route('/pdf/view/<filename>')
def view_pdf(filename):
    """
    Serve the PDF file from the uploads directory.
    """
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        return "File not found."


if __name__ == '__main__':
    app.run(debug=True)

