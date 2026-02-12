from flask import Flask, redirect, request
import urllib.parse
import idna
import os
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_allowed_domain(domain, allowed_domains):
    try:
        punycode_domain = idna.encode(domain).decode('ascii')
        return punycode_domain in allowed_domains
    except idna.IDNAError:
        return False

@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request,
    use a robust method to validate the URL,
    then redirect to the target URL
    '''
    target = request.args.get('target')

    if not target:
        logging.warning("No target URL provided.")
        return "Error: No target URL provided.", 400

    try:
        parsed_url = urllib.parse.urlparse(target)
        scheme = parsed_url.scheme.lower()
        netloc = parsed_url.netloc.lower()  # Includes domain and optionally port

        # Allowed schemes (HTTPS is strongly recommended)
        allowed_schemes = ['https']  # Only allow HTTPS
        if scheme not in allowed_schemes:
            logging.warning(f"Invalid URL scheme: {scheme}")
            return "Error: Invalid URL scheme. Only HTTPS is allowed.", 400

        # Whitelist of allowed domains.  This is the most important security measure.
        allowed_domains = ['example.com', 'www.example.com', 'safe-domain.net']  # Replace with your allowed domains

        if not is_allowed_domain(netloc, allowed_domains):
            logging.warning(f"Invalid domain: {netloc}")
            return "Error: Invalid domain.  Redirection to this domain is not allowed.", 400

        # Double check that the path is safe.  Avoid paths like "//evil.com"
        # or paths that could lead to file access vulnerabilities.  This is
        # highly application-specific.
        if parsed_url.path.startswith('//'):
            logging.warning("Invalid path: Path cannot start with '//'.")
            return "Error: Invalid path.  Path cannot start with '//'.", 400

        # Data and Javascript URI protection
        if scheme == 'data' or scheme == 'javascript':
            logging.warning(f"Invalid scheme: {scheme}")
            return "Error: Data and Javascript URIs are not allowed.", 400

        # Relative path protection (more robust)
        decoded_path = urllib.parse.unquote(parsed_url.path)
        normalized_path = os.path.normpath(decoded_path)
        if '..' in normalized_path:
            logging.warning(f"Relative paths are not allowed: {normalized_path}")
            return "Error: Relative paths are not allowed.", 400


    except Exception as e:
        logging.exception(f"Invalid URL format: {e}")
        return f"Error: Invalid URL format. {e}", 400

    logging.info(f"Redirecting to: {target}")
    return redirect(target, code=302)  # Use 302 for temporary redirect


if __name__ == '__main__':
    app.run(debug=True)

