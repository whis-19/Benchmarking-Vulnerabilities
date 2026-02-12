import os
import subprocess
from flask import Flask, request, abort
from urllib.parse import urlparse

app = Flask(__name__)

# Allowed domains/IPs -  This should be configured based on your needs.
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]
ALLOWED_FILE_EXTENSIONS = [".txt", ".pdf", ".jpg", ".png"]
UPLOAD_DIRECTORY = "/tmp/safe_uploads"  # Ensure this directory exists and has appropriate permissions

# Create the upload directory if it doesn't exist
if not os.path.exists(UPLOAD_DIRECTORY):
    try:
        os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)  # Create directory if it doesn't exist
    except OSError as e:
        print(f"Error creating directory {UPLOAD_DIRECTORY}: {e}")
        # Handle the error appropriately, e.g., log it and exit.
        raise

def is_valid_url(url):
    """
    Validates the URL against allowlist and other security checks.
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False

        if result.scheme.lower() != "https":
            print("Scheme is not HTTPS")
            return False

        hostname = result.netloc
        if ":" in hostname:
            hostname = hostname.split(":")[0]  # Remove port if present

        if hostname not in ALLOWED_DOMAINS:
            print(f"Domain {hostname} not in allowlist")
            return False

        return True
    except Exception as e:
        print(f"URL parsing error: {e}")
        return False

def sanitize_filename(filename):
    """
    Sanitizes the filename to prevent path traversal and other attacks.
    """
    # Remove any characters that aren't alphanumeric, underscores, or periods
    filename = "".join(c for c in filename if c.isalnum() or c in ('.', '_'))
    # Prevent path traversal
    filename = filename.replace("..", "")
    return filename

def is_allowed_file_extension(filename):
    """
    Checks if the file extension is in the allowlist.
    """
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_FILE_EXTENSIONS

@app.route('/curl')
def curl():
    """
    Downloads a file from a URL provided in the request, with security checks.
    """
    url = request.args.get('url')

    if not url:
        return "Error: URL parameter is missing", 400

    if not is_valid_url(url):
        return "Error: Invalid URL", 400

    try:
        # Extract filename from URL
        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path)
        filename = sanitize_filename(filename)

        if not filename:
            return "Error: Could not determine filename from URL", 400

        if not is_allowed_file_extension(filename):
            return "Error: File extension not allowed", 400

        filepath = os.path.join(UPLOAD_DIRECTORY, filename)

        # Securely download the file using subprocess with a timeout
        command = ['curl', '-s', '-f', '--connect-timeout', '10', '--max-time', '60', url, '-o', filepath]  # Added timeout and fail flag
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            print(f"Error downloading file: {stderr.decode()}")
            return "Error: Failed to download file", 500

        return f"File downloaded successfully to {filepath}", 200

    except Exception as e:
        print(f"An error occurred: {e}")
        return "Error: An unexpected error occurred", 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

