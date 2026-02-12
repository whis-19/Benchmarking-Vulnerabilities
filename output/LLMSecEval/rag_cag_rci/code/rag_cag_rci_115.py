# File Upload (Revised - with content type validation, size limit, and double extension handling)
import os
import re
import magic  # pip install python-magic
from werkzeug.utils import secure_filename
import uuid

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'
        if file:
            if len(file.read()) > MAX_FILE_SIZE:
                return "File size exceeds the limit"
            file.seek(0) # Reset file pointer after reading for size check

            original_filename = secure_filename(file.filename) # Store the original filename
            if not allowed_file(original_filename):
                return "Invalid file extension"

            # Validate content type
            mime = magic.Magic(mime=True)
            content_type = mime.from_buffer(file.read(2048)) # Read a chunk to determine type
            file.seek(0) # Reset file pointer after reading for content type check

            if not content_type.startswith('image/') and original_filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}:
                return "Invalid file content type for image"
            if not content_type == 'application/pdf' and original_filename.rsplit('.', 1)[1].lower() in {'pdf'}:
                return "Invalid file content type for PDF"
            if not content_type == 'text/plain' and original_filename.rsplit('.', 1)[1].lower() in {'txt'}:
                return "Invalid file content type for text"

            # Generate a unique filename (UUID)
            unique_filename = str(uuid.uuid4())
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            try:
                file.save(filepath)
                # In a real application, you would store the unique_filename, original_filename,
                # and content_type in a database.
                return 'File uploaded successfully'
            except Exception as e:
                logging.error(f"Error saving file: {e}")
                return "Error uploading file"

    return '''
    <!doctype html>
    <html>
    <head><title>Upload new File</title></head>
    <body>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    </body>
    </html>
    '''

