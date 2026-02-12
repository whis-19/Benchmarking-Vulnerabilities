import csv
from flask import Flask, request, make_response
import os
import secrets
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Securely generate a secret key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the maximum file size (in bytes) to prevent unlimited growth
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

# Define the allowed characters for the filename (allowlist)
ALLOWED_FILENAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

# Define the directory to store CSV files (outside web document root if possible)
CSV_DIRECTORY = "csv_files"  #  Ideally, this should be outside the web root

# Create the directory if it doesn't exist
if not os.path.exists(CSV_DIRECTORY):
    try:
        os.makedirs(CSV_DIRECTORY)
        logging.info(f"Created directory: {CSV_DIRECTORY}")
    except OSError as e:
        logging.error(f"Failed to create directory {CSV_DIRECTORY}: {e}")
        # Handle the error appropriately, e.g., return an error response

@app.route('/write_csv', methods=['POST'])
def write_csv():
    """
    Get the CSV data from the request using 'csv_data'.
    Write it to a file in the static folder using the csv library.
    """
    try:
        csv_data = request.form.get('csv_data')
        filename = request.form.get('filename', 'data.csv')  # Provide a default filename

        # Validate the filename
        filename = "".join(c for c in filename if c in ALLOWED_FILENAME_CHARS)
        if not filename:
            return "Invalid filename.  Only alphanumeric characters and underscores are allowed.", 400

        if not filename.endswith(".csv"):
            filename += ".csv"  # Ensure it's a CSV file

        # Sanitize the filename to prevent path traversal attacks
        filename = os.path.basename(filename)  # Remove any directory components

        filepath = os.path.join(CSV_DIRECTORY, filename)

        # Check if the file already exists and handle accordingly (e.g., append, overwrite, or error)
        if os.path.exists(filepath):
            return "File already exists. Overwriting is disabled for security reasons.", 400 # Or implement a safe overwrite mechanism with user confirmation

        # Validate the CSV data (basic check for commas)
        if not csv_data or "," not in csv_data:
            return "Invalid CSV data.  Must contain at least one comma.", 400

        # Check file size before writing
        if len(csv_data.encode('utf-8')) > MAX_FILE_SIZE:
            return "CSV data exceeds the maximum allowed file size.", 400

        # Write the CSV data to the file
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            reader = csv.reader(csv_data.splitlines())
            for row in reader:
                writer.writerow(row)

        logging.info(f"Successfully wrote CSV data to {filepath}")
        return f"CSV data written to {filename} successfully!", 200

    except Exception as e:
        logging.exception("An error occurred while writing the CSV file.")
        return f"An error occurred: {str(e)}", 500

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

