import os
import re
from urllib.parse import urlparse
import secrets  # Import secrets module
import filetype  # Import filetype library
from flask import Flask, request, redirect, abort, send_from_directory, Response
import logging
import io  # Import io for working with in-memory files
from PyPDF2 import PdfReader, PdfWriter

app = Flask(__name__)

# Configuration (moved to a config file or environment variables)
UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'pdf'}
ALLOWED_DOMAINS = {'example.com', '127.0.0.1'}
ALLOWED_PATHS = {  # Example of path allowlisting
    'example.com': ['/home', '/about', '/contact'],
    '127.0.0.1': ['/']
}
HTTPS_ONLY = True
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_safe_path(path, base):
    """Checks if a path is safe and does not allow path traversal."""
    if not path:
        return False

    normalized_base = os.path.abspath(base)
    normalized_path = os.path.normpath(path)  # Normalize the path
    abs_path = os.path.abspath(os.path.join(normalized_base, normalized_path))
    return normalized_base == os.path.commonpath((normalized_base, abs_path))


def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_allowed_domain(url):
    """Checks if the domain or IP address in the URL is in the allowlist."""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme  # Get the scheme (http or https)
        path = parsed_url.path

        if not hostname:
            return False  # No hostname found

        if scheme != 'https':  # Enforce HTTPS
            return False

        # Check if hostname is an IP address
        try:
            import ipaddress
            ipaddress.ip_address(hostname)  # Will raise ValueError if not an IP
            is_ip = True
        except ValueError:
            # Not an IP address
            is_ip = False

        if is_ip:
            if hostname not in ALLOWED_DOMAINS:
                return False
        else:
            if hostname not in ALLOWED_DOMAINS:
                return False

        # Path allowlisting
        if hostname in ALLOWED_PATHS:
            if path not in ALLOWED_PATHS[hostname]:
                logging.warning(f"Redirect blocked: Path {path} not allowed for domain {hostname}")
                return False
        else:
            logging.warning(f"Redirect blocked: No paths defined for domain {hostname}")
            return False

        return True

    except Exception as e:
        logging.error(f"Error parsing URL: {e}")
        return False


def sanitize_filename(filename):
    """Sanitizes a filename to remove unsafe characters.  Handles Unicode."""
    filename = re.sub(r'[^\w\.\-]', '', filename, flags=re.UNICODE)  # Allow Unicode word characters
    return os.path.basename(filename)  # Always remove leading directory components


@app.before_request
def before_request():
    """Enforces HTTPS for all routes if HTTPS_ONLY is enabled."""
    if HTTPS_ONLY and not request.is_secure:
        return redirect(request.url.replace("http://", "https://"), code=302)


def strip_pdf_metadata(pdf_content):
    """Strips metadata from a PDF file."""
    try:
        reader = PdfReader(io.BytesIO(pdf_content))
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        # Remove metadata
        writer.remove_metadata()

        # Get the modified PDF content
        output_stream = io.BytesIO()
        writer.write(output_stream)
        return output_stream.getvalue()
    except Exception as e:
        logging.error(f"Error stripping metadata: {e}")
        return pdf_content  # Return original content on error


@app.route('/pdf/upload', methods=['POST'])
def upload_pdf():
    """Handles PDF file uploads, ensuring security."""
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file part", 400

        file = request.files['file']

        if file.filename == '':
            return "No selected file", 400

        if file:
            # Validate file extension
            if not allowed_file(file.filename):
                return "Invalid file type. Only PDF files are allowed.", 400

            try:
                file_content = file.read()
                # Re-validate file content (optional, but recommended)
                kind = filetype.guess(file_content[:2048])
                if kind is None or kind.mime != 'application/pdf':
                    return "Invalid file content after read.", 400

                # Strip metadata
                file_content = strip_pdf_metadata(file_content)

                # Sanitize the filename
                original_filename = file.filename
                filename = sanitize_filename(original_filename)

                # Generate a secure, unique filename
                secure_filename = secrets.token_hex(16) + "." + filename.rsplit('.', 1)[1].lower()
                filepath = os.path.join(UPLOAD_FOLDER, secure_filename)

                # Check for path traversal BEFORE saving
                if not is_safe_path(filepath, os.path.abspath(UPLOAD_FOLDER)):
                    return "Invalid file path", 400

                with open(filepath, 'wb') as f:  # Write in binary mode
                    f.write(file_content)

                # Set file permissions (restrictive)
                os.chmod(filepath, 0o400)  # Owner read-only

                # Store original_filename and secure_filename in a database (not shown)
                # ...

                # Redirect to view the PDF (after successful upload) - use secure_filename
                logging.info(f"File uploaded successfully: {secure_filename} (original: {original_filename})")
                return redirect('/pdf/view/' + secure_filename)

            except OSError as e:  # Catch specific exceptions
                logging.error(f"Error saving file (OSError): {e}")
                return "Error saving file (OSError)", 500
            except Exception as e:
                logging.error(f"Error processing file: {e}")
                return "Error processing file", 500

        else:
            return "Invalid file type. Only PDF files are allowed.", 400

    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''


@app.route('/pdf/view/<filename>')
def view_pdf(filename):
    """Serves the PDF file, ensuring security."""
    # Sanitize the filename (although it should already be sanitized)
    filename = sanitize_filename(filename)

    filepath = os.path.join(UPLOAD_FOLDER, filename)

    # Check for path traversal
    if not is_safe_path(filepath, os.path.abspath(UPLOAD_FOLDER)):
        abort(404)

    try:
        # Serve the file using send_from_directory (more secure than send_file)
        response = send_from_directory(UPLOAD_FOLDER, filename)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Content-Disposition'] = f'inline; filename="{filename}"'  # Or 'attachment'
        return response
    except FileNotFoundError:
        abort(404)


@app.route('/redirect')
def redirect_url():
    """Demonstrates secure URL redirection."""
    target_url = request.args.get('url')

    if not target_url:
        return "No URL provided", 400

    if is_allowed_domain(target_url):
        # Consider a confirmation page here for added security
        logging.info(f"Redirecting to: {target_url}")
        return redirect(target_url)
    else:
        logging.warning(f"Redirect blocked: {target_url} not allowed")
        return "URL not allowed", 403


if __name__ == '__main__':
    # Never use debug=True in production!
    # Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=False, ssl_context='adhoc')  # Enable SSL for local testing.  Use proper certificates in production.

