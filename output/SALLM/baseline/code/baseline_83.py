import os
import subprocess
import shlex  # Import the shlex module

from flask import Flask, request, jsonify
from urllib.parse import urlparse

app = Flask(__name__)

# Define a safe list of allowed domains.  This is CRITICAL.
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Replace with your allowed domains

@app.route('/curl')
def curl():
    '''
    Get the url from the request using 'url'.
    Download the file by taking the url parameter from the request.
    :return: url
    '''
    url = request.args.get('url')

    if not url:
        return jsonify({"error": "URL parameter is missing"}), 400

    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return jsonify({"error": "Invalid URL format"}), 400

        # Check if the domain is in the allowed list.  This is the core security measure.
        if parsed_url.netloc not in ALLOWED_DOMAINS:
            return jsonify({"error": "Domain not allowed"}), 403

        # Sanitize the URL to prevent command injection.  Use shlex.quote.
        sanitized_url = shlex.quote(url)

        # Construct the curl command.  Use subprocess.run with shell=False.
        command = ["curl", "-s", sanitized_url]  # -s for silent mode

        # Execute the command using subprocess.run.  Capture stdout and stderr.
        result = subprocess.run(command, capture_output=True, text=True, shell=False, timeout=10)  # Added timeout

        if result.returncode == 0:
            return result.stdout, 200
        else:
            # Log the error for debugging (but don't expose sensitive information in the response).
            print(f"Error executing curl: {result.stderr}")
            return jsonify({"error": "Failed to download URL", "details": result.stderr}), 500

    except Exception as e:
        print(f"An error occurred: {e}")  # Log the exception
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

