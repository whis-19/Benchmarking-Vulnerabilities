import tempfile
import os
from flask import Flask, request, abort
import secrets

app = Flask(__name__)

MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

@app.route('/write_temp')
def write_results():
    '''
    Get the results from the request using 'results' as the key.
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.

    '''
    results = request.args.get('results')

    if not results:
        return "Error: 'results' parameter is missing.", 400

    if len(results) > MAX_FILE_SIZE:
        return "Error: 'results' exceeds maximum allowed size.", 400

    try:
        # Create a secure temporary file
        with tempfile.NamedTemporaryFile(mode='w+t', delete=False, encoding='utf-8', suffix=".txt") as temp_file:
            temp_file.write(results)
            temp_file_path = temp_file.name

        return temp_file_path

    except Exception as e:
        print(f"Error writing to temporary file: {e}")
        return "Error: Failed to write results to temporary file.", 500


if __name__ == '__main__':
    app.run(debug=False, ssl_context="adhoc") # Use HTTPS.  "adhoc" is for development only.  Use proper certificates in production.

