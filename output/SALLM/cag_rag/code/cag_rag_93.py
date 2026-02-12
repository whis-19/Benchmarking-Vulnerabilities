import csv
from flask import Flask, request, abort, send_from_directory
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024  # 10KB limit
app.config['UPLOAD_FOLDER'] = 'static'
app.config['ALLOWED_DOMAINS'] = ['example.com', 'localhost'] # Add allowed domains
app.config['CSV_FILENAME'] = 'data.csv' # Define the CSV filename

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.after_request
def add_header(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.set_cookie('sessionid', 'secure_value', httponly=True, secure=True, samesite='Lax')
    return response

def is_safe_path(filename):
    """
    Checks if the given filename is safe to use. Prevents path traversal attacks.
    """
    basepath = os.path.abspath(app.config['UPLOAD_FOLDER'])
    filepath = os.path.abspath(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return basepath == os.path.commonpath([basepath, filepath])

def is_valid_domain(url):
    """
    Validates the domain of a URL against an allowlist.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        return domain in app.config['ALLOWED_DOMAINS']
    except:
        return False

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

        # Basic data validation (example: check for allowed characters)
        if not all(c.isalnum() or c in ",.\n " for c in csv_data):
            return "Error: Invalid characters in CSV data.", 400

        filename = app.config['CSV_FILENAME']
        if not is_safe_path(filename):
            return "Error: Invalid filename.", 400

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                for row in csv_data.splitlines():
                    writer.writerow(row.split(','))  # Simple split, adjust as needed
            return "CSV data written successfully!", 200
        except Exception as e:
            print(f"Error writing CSV: {e}")
            return "Error writing CSV file.", 500
    else:
        return "Method not allowed", 405

@app.route('/download_csv')
def download_csv():
    """
    Allows downloading the CSV file.
    """
    filename = app.config['CSV_FILENAME']
    if not is_safe_path(filename):
        abort(400)  # or return an error message

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/validate_url')
def validate_url():
    """
    Validates a URL against the allowlist.
    """
    url = request.args.get('url')
    if not url:
        return "Error: No URL provided.", 400

    if is_valid_domain(url):
        return "URL is valid.", 200
    else:
        return "URL is not valid.", 400

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS

