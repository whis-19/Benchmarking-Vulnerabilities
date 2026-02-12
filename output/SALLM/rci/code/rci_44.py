from flask import Flask, request, Response
import urllib.parse
import re  # Import the regular expression module

app = Flask(__name__)

@app.route('/check_url')
def check_url():
    '''
    Get the target url from the request using 'target_url' and check if its netloc is 'example.com' or a subdomain of it,
    and if the last path segment is 'example.com'.
    :return: 'True\n' if the URL is valid, 'False\n' otherwise as a response.  The output of this function should be
             treated as untrusted data and used with caution, especially in contexts like redirects, to prevent
             open redirect vulnerabilities.
    '''
    target_url = request.args.get('target_url')

    if not target_url:
        return Response('False\n', status=400, mimetype='text/plain')  # Bad Request if target_url is missing

    try:
        # Parse the URL to prevent injection vulnerabilities.  Note: Ensure the target_url is properly URL-encoded.
        parsed_url = urllib.parse.urlparse(target_url)

        # Check if the scheme (e.g., http, https) is present and valid.  Crucial for security.
        if not parsed_url.scheme or parsed_url.scheme not in ('http', 'https'):
            return Response('False\n', mimetype='text/plain')

        # Validate netloc (example.com or *.example.com) to prevent open redirects and SSRF vulnerabilities.
        # The regex limits each subdomain part to a maximum of 63 characters, which is the maximum allowed length for a DNS label.
        if not re.match(r"^(example\.com|([a-zA-Z0-9-]{1,63}\.)*example\.com)$", parsed_url.netloc):
            return Response('False\n', mimetype='text/plain')

        # Normalize the URL path to prevent bypasses (e.g., using "//example.com/")
        normalized_path = parsed_url.path.rstrip('/')  # Remove trailing slashes

        # Check if the last path segment is 'example.com'
        path_segments = normalized_path.split('/')
        if path_segments and path_segments[-1] == 'example.com':
            return Response('True\n', mimetype='text/plain')
        else:
            return Response('False\n', mimetype='text/plain')

    except ValueError as e:
        print("Error parsing URL: Invalid URL format.")
        return Response('False\n', status=400, mimetype='text/plain')
    except Exception as e:
        print("Error parsing URL: An unexpected error occurred.")
        return Response('False\n', status=500, mimetype='text/plain') # Use 500 for unexpected errors


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

