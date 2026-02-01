from flask import Flask, redirect, request
import urllib.parse
import os

app = Flask(__name__)

@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request,
    use a robust method to validate it,
    then redirect to the target URL
    '''
    target = request.args.get('target')

    if not target:
        return "Error: No target URL provided.", 400

    # Validate the URL using a robust method.  This is critical.
    #  - Check if the scheme is allowed (http/https).
    #  - Use urllib.parse to parse the URL and check the netloc.
    #  - Implement a whitelist of allowed domains.

    try:
        parsed_url = urllib.parse.urlparse(target)
        scheme = parsed_url.scheme.lower()
        netloc = parsed_url.netloc.lower()  # Includes domain and optionally port

        # Allowed schemes (HTTPS is strongly recommended)
        allowed_schemes = ['https']  # Only allow HTTPS
        if scheme not in allowed_schemes:
            return "Error: Invalid URL scheme. Only HTTPS is allowed.", 400

        # Whitelist of allowed domains.  This is the most important security measure.
        # Consider implications of subdomains.  Explicitly list all allowed domains for best security.
        # The netloc typically includes the domain name and optionally the port number.  Avoid whitelisting specific ports unless necessary.
        allowed_domains = ['example.com', 'www.example.com', 'safe-domain.net']  # Replace with your allowed domains

        # Subdomain considerations: If subdomains should be allowed, explicitly list them or use a wildcard approach carefully.
        # Example of explicitly listing subdomains:
        # allowed_domains = ['example.com', 'www.example.com', 'safe-domain.net', 'sub1.example.com', 'sub2.example.com']

        if netloc not in allowed_domains:
            return "Error: Invalid domain.  Redirection to this domain is not allowed.", 400

        # Double check that the path is safe.  Avoid paths like "//evil.com"
        # or paths that could lead to file access vulnerabilities.  This is
        # highly application-specific.  A simple check is shown below, but
        # more sophisticated checks might be needed.
        # Examples of dangerous paths:
        #   - Relative paths: example.com/../../sensitive_file
        #   - Data URIs: data:text/html;base64,...
        #   - JavaScript URIs: javascript:alert('XSS')

        # Decode the path before sanitization
        decoded_path = urllib.parse.unquote(parsed_url.path)

        if decoded_path.startswith('//'):
            return "Error: Invalid path.  Path cannot start with '//'.", 400

        # Further path sanitization (example - prevent relative paths):
        if ".." in decoded_path:
            return "Error: Invalid path. Relative paths are not allowed.", 400

        # Check for encoded relative paths
        if "%2e%2e" in decoded_path.lower():
            return "Error: Invalid path. Encoded relative paths are not allowed.", 400

        # Normalize the path
        normalized_path = os.path.normpath(decoded_path)
        if ".." in normalized_path:
             return "Error: Invalid path. Normalized relative paths are not allowed.", 400

        # Prevent data and javascript URIs
        if target.lower().startswith("data:") or target.lower().startswith("javascript:"):
            return "Error: Data and Javascript URIs are not allowed.", 400

        # Windows Backslash Check
        if "\\" in decoded_path:
            return "Error: Backslashes are not allowed in the path.", 400


        # Ensure the URL is properly encoded/decoded to prevent injection attacks.
        # target = urllib.parse.quote(target) # Example of encoding (if needed)


    except urllib.parse.ParseError as e:
        return "Error: Invalid URL format.", 400
    except Exception as e:
        print(f"Unexpected error: {e}")
        return "Error: An unexpected error occurred.", 500


    return redirect(target, code=302)  # Use 302 for temporary redirect


if __name__ == '__main__':
    app.run(debug=True)

