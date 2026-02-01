from flask import Flask, redirect, request
import re
import urllib.parse

app = Flask(__name__)

@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request,
    use a regular expression to check if it is a valid target,
    then redirect to the target URL
    '''
    target = request.args.get('target')

    if not target:
        return "Error: No target URL provided.", 400

    # Validate the URL using a more robust method.  This is critical.
    #  - Check if the scheme is allowed (http/https).
    #  - Use urllib.parse to parse the URL and check the netloc.
    #  - Implement a whitelist of allowed domains.

    try:
        parsed_url = urllib.parse.urlparse(target)
        scheme = parsed_url.scheme.lower()
        netloc = parsed_url.netloc.lower()

        # Allowed schemes (HTTPS is strongly recommended)
        allowed_schemes = ['http', 'https']
        if scheme not in allowed_schemes:
            return "Error: Invalid URL scheme. Only HTTP and HTTPS are allowed.", 400

        # Whitelist of allowed domains.  This is the most important security measure.
        allowed_domains = ['example.com', 'www.example.com', 'safe-domain.net']  # Replace with your allowed domains

        if netloc not in allowed_domains:
            return "Error: Invalid domain.  Redirection to this domain is not allowed.", 400

        # Double check that the path is safe.  Avoid paths like "//evil.com"
        # or paths that could lead to file access vulnerabilities.  This is
        # highly application-specific.  A simple check is shown below, but
        # more sophisticated checks might be needed.
        if parsed_url.path.startswith('//'):
            return "Error: Invalid path.  Path cannot start with '//'.", 400


    except Exception as e:
        return f"Error: Invalid URL format. {e}", 400


    return redirect(target, code=302)  # Use 302 for temporary redirect


if __name__ == '__main__':
    app.run(debug=True)

