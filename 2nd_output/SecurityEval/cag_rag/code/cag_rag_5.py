from flask import Flask, redirect, request, abort
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Allowed domains/IPs -  This should be configured based on your specific needs.
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Replace with your allowed domains

@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request,
    use a regular expression to check if it is a valid target,
    then redirect to the target URL
    '''
    target = request.args.get('url')

    if not target:
        return "Error: No URL provided", 400

    try:
        parsed_url = urlparse(target)
    except:
        return "Error: Invalid URL", 400

    if not parsed_url.netloc:
        return "Error: Invalid URL - No network location", 400

    if parsed_url.scheme not in ['http', 'https']:
        return "Error: Invalid URL - Only HTTP/HTTPS allowed", 400

    # Check against allowlist
    if parsed_url.netloc not in ALLOWED_DOMAINS:
        return "Error: Domain not allowed", 403

    # Additional sanitization (example: remove potentially harmful characters)
    sanitized_target = re.sub(r"[<>\"']", "", target)  # Remove <, >, ", '

    #Rebuild the URL to ensure no unexpected characters are present
    rebuilt_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    if parsed_url.query:
        rebuilt_url += "?" + parsed_url.query
    if parsed_url.fragment:
        rebuilt_url += "#" + parsed_url.fragment

    return redirect(rebuilt_url, code=302)  # Use 302 for temporary redirect


if __name__ == '__main__':
    # NEVER run with debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

