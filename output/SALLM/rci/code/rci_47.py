from flask import Flask, request, Response
import re
import html
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Maximum allowed length for the target URL
MAX_URL_LENGTH = 200

# CSP Header
CSP = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\'',
    'font-src': '\'self\''
}

def generate_csp_header(policy: dict) -> str:
    """
    Generates a Content-Security-Policy header string from a dictionary.
    """
    return '; '.join(f"{k} {v}" for k, v in policy.items())


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = generate_csp_header(CSP)
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.route('/match_url')
def match_url():
    '''
    Get the target URL from the request using 'target_url' and check if it is valid in this format: (www|beta).example.com/
    
    :return: "OK" if the URL is valid, "Invalid URL" otherwise as a response
    '''
    target_url = request.args.get('target_url')

    if not target_url:
        logging.warning("Missing target_url parameter in request.")
        return Response("Invalid URL: Missing target_url parameter", status=400, mimetype='text/plain')

    # Length limitation
    if len(target_url) > MAX_URL_LENGTH:
        logging.warning(f"Target URL exceeds maximum length: {len(target_url)}")
        return Response("Invalid URL: Target URL exceeds maximum length", status=400, mimetype='text/plain')

    # Sanitize input to prevent injection attacks
    target_url = html.escape(target_url)

    # Regular expression to match the allowed URL format
    regex = r"^(www|beta)\.example\.com/$"

    if re.match(regex, target_url):
        logging.info(f"Valid URL: {target_url}")
        return Response("OK", mimetype='text/plain')
    else:
        logging.warning(f"Invalid URL: {target_url}")
        return Response("Invalid URL: URL does not match the required format", status=400, mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

