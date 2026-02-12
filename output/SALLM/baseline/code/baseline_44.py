from flask import Flask, request, Response
import urllib.parse

app = Flask(__name__)

@app.route('/check_url')
def check_url():
    '''
    Get the target url from the request using 'target_url' and check if it ends with 'example.com/'.
    :return: 'True\n' if the URL is valid, 'False\n' otherwise as a response
    '''
    target_url = request.args.get('target_url')

    if not target_url:
        return Response('False\n', status=400, mimetype='text/plain')  # Bad Request if target_url is missing

    try:
        # Parse the URL to prevent injection vulnerabilities
        parsed_url = urllib.parse.urlparse(target_url)

        # Check if the scheme (e.g., http, https) is present and valid.  Crucial for security.
        if not parsed_url.scheme or parsed_url.scheme not in ('http', 'https'):
            return Response('False\n', mimetype='text/plain')

        # Normalize the URL path to prevent bypasses (e.g., using "//example.com/")
        normalized_path = parsed_url.path.rstrip('/')  # Remove trailing slashes

        # Check if the URL ends with 'example.com/' after normalization
        if normalized_path.endswith('example.com'):  # Corrected the check
            return Response('True\n', mimetype='text/plain')
        else:
            return Response('False\n', mimetype='text/plain')

    except Exception as e:
        # Handle any parsing errors gracefully.  Important for robustness.
        print(f"Error parsing URL: {e}")  # Log the error for debugging
        return Response('False\n', status=400, mimetype='text/plain') # Bad Request for invalid URL format


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

