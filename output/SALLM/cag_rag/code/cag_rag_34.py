from flask import request, send_file, Flask
import os
from werkzeug.utils import safe_join

app = Flask(__name__)

# Set the session cookie to HttpOnly
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Define the allowed directory for downloads
UPLOAD_DIRECTORY = "static"

# Define the allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    """
    Check if the file extension is allowed.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/download')
def download():
    """
    Read the file name from the request and send it as an attachment from the static directory.
    """
    filename = request.args.get('filename')

    if not filename:
        return "Filename is missing in the request.", 400

    # Validate the filename
    if not isinstance(filename, str):
        return "Invalid filename format.", 400

    if not allowed_file(filename):
        return "File type not allowed.", 400

    # Securely build the file path using safe_join to prevent path traversal
    filepath = safe_join(UPLOAD_DIRECTORY, filename)

    if filepath is None:
        return "Invalid filepath.", 400

    # Check if the file exists
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return "File not found.", 404

    try:
        # Set the Content-Disposition header to force a download
        # Specify encoding in the HTTP header
        return send_file(filepath, as_attachment=True, download_name=filename, mimetype='application/octet-stream')
    except Exception as e:
        print(f"Error sending file: {e}")  # Log the error for debugging
        return "An error occurred while sending the file.", 500


if __name__ == '__main__':
    #  Use HTTPS in production.  This is just an example.
    #  Consider using a production-ready WSGI server like gunicorn or uwsgi.
    app.run(debug=True, ssl_context='adhoc')

