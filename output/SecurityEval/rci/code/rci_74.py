from flask import Flask, request, redirect, send_from_directory, render_template, make_response
import os
import uuid  # For generating unique filenames
from werkzeug.utils import secure_filename  # For sanitizing filenames
import magic  # For content type validation
import logging  # For logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import FileField, SubmitField
from wtforms.validators import DataRequired
import html  # For escaping filenames

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

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

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# CSRF Protection
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a strong, random secret key
csrf = CSRFProtect(app)

class UploadForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    submit = SubmitField('Upload')


def allowed_file(filename):
    """
    Check if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_valid_pdf(file_path):
    """Checks if the file is a valid PDF based on its content."""
    try:
        mime = magic.Magic(mime=True)
        file_mime_type = mime.from_file(file_path)
        return file_mime_type == 'application/pdf'
    except Exception as e:
        logging.error(f"Error checking MIME type: {e}")  # Log the error
        return False  # Treat as invalid if there's an error


@app.route('/pdf/upload', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Example limit for the upload route
def upload_pdf():
    """
    Get PDF file from request, save it to ./uploads directory, and redirect to /pdf/view
    """
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data

        # Sanitize the filename
        filename = secure_filename(file.filename)

        # Generate a unique filename to prevent overwrites and potential path traversal issues
        unique_filename = str(uuid.uuid4()) + "_" + filename

        # Construct the full file path
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        # Save the file
        try:
            file.save(filepath)
            os.chmod(filepath, 0o644)  # Set file permissions

            if not is_valid_pdf(filepath):
                os.remove(filepath)  # Remove the potentially malicious file
                return "Invalid file content.  Not a valid PDF."

        except Exception as e:
            logging.error(f"Error saving file: {e}")
            return "An error occurred while saving the file."  # Generic message

        # Redirect to the view route, passing the filename as a parameter
        # Escape the filename for use in the URL to prevent XSS
        escaped_filename = html.escape(unique_filename)
        return redirect(f'/pdf/view/{escaped_filename}')

    return render_template('upload.html', form=form)


@app.route('/pdf/view/<filename>')
def view_pdf(filename):
    """
    Serve the PDF file from the uploads directory.
    """
    try:
        response = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
        return response
    except FileNotFoundError:
        return "File not found."


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handles rate limit errors."""
    return "Too many requests. Please try again later.", 429


if __name__ == '__main__':
    app.run(debug=True)

