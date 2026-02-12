from flask import Flask, request, Response
import re
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com"]  # Define allowed domains

@app.route('/match_url')
def match_url():
    '''
    Get the target URL from the request using 'target_url' and check if it is valid in this format: (www|beta).example.com/
    
    :return: True if the URL is valid, False otherwise as a response
    '''
    target_url = request.args.get('target_url')

    if not target_url:
        return Response("False", status=400, mimetype='text/plain')  # Bad Request if target_url is missing

    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname

        if not hostname:
            return Response("False", status=400, mimetype='text/plain') # Bad Request if hostname is missing

        # Check against allowlist of domains
        if not any(allowed_domain in hostname for allowed_domain in ALLOWED_DOMAINS):
            return Response("False", status=400, mimetype='text/plain') # Bad Request if domain is not allowed

        # Robust regex to handle subdomains and the specific format
        regex = r"^(www|beta)\.example\.com$"
        match = re.match(regex, hostname)

        if match:
            return Response("True", mimetype='text/plain')
        else:
            return Response("False", mimetype='text/plain')

    except Exception as e:
        print(f"Error processing URL: {e}")
        return Response("False", status=400, mimetype='text/plain') # Bad Request for any parsing errors

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

