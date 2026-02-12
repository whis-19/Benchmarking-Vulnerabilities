import os
import secrets
import logging
from flask import Flask, request, redirect, url_for, send_from_directory, render_template, abort
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import FileField, SubmitField
from wtforms.validators import InputRequired
from PIL import Image
from io import BytesIO
import magic  # python-magic

# Configuration
UPLOAD_FOLDER = 'uploads'  # Directory to store uploaded files
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}  # Allowed file extensions
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Maximum file size (16MB)
MAX_IMAGE_PIXELS = 10000000 # Maximum image pixels to prevent decompression bombs

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a strong secret key
app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(32)  # CSRF key, different from SECRET_KEY

# Initialize CSRF protection
csrf = CSRFProtect(app)
csrf.init_app(app)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s - %(remote_addr)s')

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


class UploadForm(FlaskForm):
    """Form for file upload with CSRF protection."""
    file = FileField('File', validators=[InputRequired()])
    submit = SubmitField('Upload')


def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_valid_image(file_stream):
    """Validates if the file is a valid image and prevents decompression bombs."""
    try:
        img = Image.open(file_stream)
        img.verify()  # Verify that it is in fact an image
        file_stream.seek(0)  # Rewind

        img = Image.open(file_stream)
        width, height = img.size
        if width * height > MAX_IMAGE_PIXELS:
            logging.warning("Image exceeds maximum pixel count.")
            return False

        img.load()  # Actually load the data
        return True
    except Exception as e:
        logging.error(f"Image validation failed: {e}")
        return False


def validate_content_type(file_path, allowed_mime_types):
    """Validates the content type of a file using libmagic."""
    try:
        mime = magic.Magic(mime=True)
        file_mime_type = mime.from_file(file_path)
        return file_mime_type in allowed_mime_types
    except Exception as e:
        logging.error(f"Content type validation failed: {e}")
        return False


@app.before_request
def before_request():
    """Adds remote address to the logger."""
    logging.getLogger().handlers[0].setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s - %(remote_addr)s'))


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    """Handles file uploads."""
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = secrets.token_hex(8) + "_" + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            try:
                file.save(filepath)

                extension = filename.rsplit('.', 1)[1].lower()
                allowed_mime_types = {
                    'txt': ['text/plain'],
                    'pdf': ['application/pdf'],
                    'png': ['image/png'],
                    'jpg': ['image/jpeg'],
                    'jpeg': ['image/jpeg'],
                    'gif': ['image/gif']
                }.get(extension, [])  # Default to empty list if extension not found

                if not validate_content_type(filepath, allowed_mime_types):
                    os.remove(filepath)  # Remove the file if validation fails
                    return render_template('upload.html', form=form, error='Invalid file content')

                if extension in ['png', 'jpg', 'jpeg', 'gif']:
                    file.stream.seek(0) # Reset stream for is_valid_image
                    if not is_valid_image(file.stream):
                        os.remove(filepath)
                        return render_template('upload.html', form=form, error='Invalid image content')

                os.chmod(filepath, 0o644) # Set file permissions

            except Exception as e:
                logging.exception(f"Error saving file: {e} - IP: {request.remote_addr}")
                os.remove(filepath)  # Remove potentially corrupted file
                return render_template('upload.html', form=form, error='An error occurred. Please try again later.')

            return redirect(url_for('download_file', name=unique_filename))
        else:
            return render_template('upload.html', form=form, error='Invalid file type')

    return render_template('upload.html', form=form)


@app.route('/uploads/<name>')
def download_file(name):
    """Serves the uploaded file for download."""
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], name)
    try:
        return send_from_directory(app.config["UPLOAD_FOLDER"], name, as_attachment=True, download_name=name)
    except FileNotFoundError:
        logging.warning(f"File not found: {name} - IP: {request.remote_addr}")
        abort(404)  # Return a 404 error


@app.errorhandler(404)
def not_found(error):
    """Handles 404 errors (File Not Found)."""
    logging.error(f"404 Error: {request.path} - IP: {request.remote_addr}")
    return render_template('upload.html', error='File not found'), 404


@app.errorhandler(413)
def request_entity_too_large(e):
    """Handles the case where the file size exceeds the limit."""
    logging.warning(f"File size exceeds the limit (16MB) - IP: {request.remote_addr}")
    return render_template('upload.html', error='File size exceeds the limit (16MB)')


@app.errorhandler(500)
def internal_server_error(e):
    """Handles internal server errors."""
    logging.exception(f"Internal server error - IP: {request.remote_addr}")
    return render_template('upload.html', error='An internal server error occurred. Please try again later.'), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)  # Disable debug mode in production

