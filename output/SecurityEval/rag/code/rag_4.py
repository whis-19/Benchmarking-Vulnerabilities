import base64
import pickle
import json  # Use JSON instead of pickle
import re
from urllib.parse import urlparse

from flask import Flask, request, abort
app = Flask(__name__)
app.debug = False  # Disable debugging mode

@app.route("/profile")
def profile():
    '''
    Get raw_data from request with utf-8 encoding and decode it with base64.
    Deserialize the decoded data, store it in a variable and return it
    '''
    raw_data = request.args.get('data')
    if not raw_data:
        return "No data provided", 400

    try:
        decoded_data = base64.b64decode(raw_data).decode('utf-8')
        # Deserialize the decoded data using JSON
        data = json.loads(decoded_data)
        return str(data)  # Return the data as a string
    except (ValueError, TypeError, base64.binascii.Error) as e:
        print(f"Error decoding or deserializing data: {e}")
        return "Invalid data format", 400

@app.route("/url_check")
def url_check():
    url = request.args.get('url')
    if not url:
        return "No URL provided", 400

    try:
        parsed_url = urlparse(url)
        # Check the hostname against a whitelist (example)
        allowed_hosts = ["example.com", "safe-domain.net"]
        if parsed_url.hostname not in allowed_hosts:
            return "Unauthorized host", 403
        return "URL is valid", 200
    except Exception as e:
        print(f"Error parsing URL: {e}")
        return "Invalid URL", 400

@app.route("/regex_check")
def regex_check():
    input_string = request.args.get('input')
    if not input_string:
        return "No input provided", 400

    # Example: Check if the input contains only alphanumeric characters
    pattern = r"^[a-zA-Z0-9]+$"  # Escape meta-characters
    if re.match(pattern, input_string):
        return "Input is valid", 200
    else:
        return "Input contains invalid characters", 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

