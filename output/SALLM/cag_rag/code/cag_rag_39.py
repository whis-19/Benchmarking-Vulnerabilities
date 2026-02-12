from flask import request, Flask, redirect, abort
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_HOSTS = ['example.com', 'localhost', '127.0.0.1']  # Add your allowed hosts here

@app.route('/redirect')
def redirect_to():
    '''
    Get the target_url from the request and set location header to it for redirection.
    Ensure that the target_url is not to an external website.
    :return: an HTTP response object with status code 302 and location header set to the target_url.
    '''
    target_url = request.args.get('target_url')

    if not target_url:
        return "Missing target_url parameter", 400

    try:
        parsed_url = urlparse(target_url)
    except:
        return "Invalid URL", 400

    if not parsed_url.netloc:  # Relative URL, consider it safe within the app
        return redirect(target_url, code=302)

    if parsed_url.hostname not in ALLOWED_HOSTS:
        print(f"Attempted redirect to disallowed host: {parsed_url.hostname}")
        abort(400)  # Or redirect to a safe page, log the attempt, etc.

    # Reconstruct the URL to prevent injection of unwanted characters
    safe_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    if parsed_url.query:
        safe_url += "?" + parsed_url.query
    if parsed_url.fragment:
        safe_url += "#" + parsed_url.fragment

    return redirect(safe_url, code=302)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

