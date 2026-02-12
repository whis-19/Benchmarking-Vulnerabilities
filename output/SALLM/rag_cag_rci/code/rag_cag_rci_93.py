import csv
import os
from flask import Flask, request, abort, send_from_directory
from urllib.parse import urlparse

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024  # 10KB limit to prevent large file uploads
app.config['UPLOAD_FOLDER'] = 'static'  # Define the upload folder
app.config['ALLOWED_DOMAINS'] = ['example.com', 'localhost'] # Example allowed domains

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Set HttpOnly flag for session cookie (if you're using sessions)
# Example:
# app.config['SESSION_COOKIE_HTTPONLY'] = True

@app.after_request
def add_header(response):
    """
    Add headers for security best practices.
    """
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


def is_valid_domain(url):
    """
    Validate the domain against an allowlist.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        return domain in app.config['ALLOWED_DOMAINS']
    except:
        return False

def is_safe_filename(filename):
    """
    Check if the filename is safe to use.  Prevents path traversal.
    """
    if not filename:
        return False
    
    # Check for path traversal patterns
    if ".." in filename:
        return False

    # Check for disallowed characters (example: only allow alphanumeric and underscores)
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    for char in filename:
        if char not in allowed_chars and char != '.': # Allow dot for extension
            return False

    return True

def allowed_file(filename):
    """
    Check if the file extension is allowed.
    """
    ALLOWED_EXTENSIONS = {'csv'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/write_csv', methods=['POST'])
def write_csv():
    """
    Get the csv data from the request using 'csv_data'.
    Write it to a file in the static folder using csv library.
    """
    if request.method == 'POST':
        csv_data = request.form.get('csv_data')

        if not csv_data:
            return "Error: No CSV data provided.", 400

        # Validate the data (example: check for expected format)
        # This is a crucial step to prevent malicious data injection
        # Example: Check if it's a valid CSV string
        try:
            csv.reader([csv_data]) # Try to parse it as CSV
        except Exception as e:
            return f"Error: Invalid CSV data: {e}", 400

        filename = "data.csv"  # Fixed filename to avoid user-controlled filenames
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Write the data to the file
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                # Assuming the data is a single string representing the entire CSV content
                # You might need to parse the string into rows if it's not already in that format
                for row in csv.reader([csv_data]):
                    writer.writerow(row)

            return "CSV data written successfully!", 200

        except Exception as e:
            return f"Error writing to file: {e}", 500

    return "Method not allowed", 405


@app.route('/download/<filename>')
def download_file(filename):
    """
    Serve files from the upload folder.  Requires filename validation.
    """
    if not is_safe_filename(filename) or not allowed_file(filename):
        abort(400)  # Or return an error message

    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)


if __name__ == '__main__':
    app.run(debug=False, ssl_context='adhoc') # Use HTTPS.  'adhoc' is for development only.  Use proper certificates in production.

