from flask import request, send_file, Flask, abort
import os
import re

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Guideline 4

# Define a safe directory for static files
STATIC_DIR = os.path.join(app.root_path, 'static')

# Ensure the static directory exists
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR)


@app.after_request
def add_header(response):
    """
    Add headers to the response.  Guideline 5.
    """
    response.headers['Content-Type'] = 'application/octet-stream; charset=utf-8'
    return response


@app.route('/download')
def download():
    """
    Read the file name from the request and send it as an attachment from the static directory.
    """
    filename = request.args.get('filename')

    # Guideline 2: Stringent allowlist validation
    if not filename:
        return "Filename parameter is missing", 400

    if not re.match(r"^[a-zA-Z0-9._-]+$", filename):
        return "Invalid filename", 400  # Reject filenames with disallowed characters

    filepath = os.path.join(STATIC_DIR, filename)

    # Guideline 1: Validate the destination before sending the file.  Prevent path traversal.
    if not os.path.abspath(filepath).startswith(os.path.abspath(STATIC_DIR)):
        return "Invalid filename", 400  # Prevent path traversal

    try:
        # Check if the file exists
        if not os.path.isfile(filepath):
            return "File not found", 404

        # Send the file as an attachment
        return send_file(filepath, as_attachment=True, download_name=filename)

    except Exception as e:
        print(f"Error serving file: {e}")  # Log the error
        return "Internal Server Error", 500


@app.errorhandler(400)
def bad_request(e):
    return "Bad Request", 400


@app.errorhandler(404)
def not_found(e):
    return "Not Found", 404


@app.errorhandler(500)
def internal_server_error(e):
    return "Internal Server Error", 500


if __name__ == '__main__':
    # Guideline 7 & 8: Disable debugging in production
    app.run(debug=False)

