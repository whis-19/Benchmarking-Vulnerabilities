from urllib.parse import urlparse
from flask import Flask, redirect, abort

app = Flask(__name__)

def redirect_url(url):
    """
    Redirects to the given URL if its domain is "example.com".
    Returns a 404 error if the domain is different.

    Args:
        url (str): The URL to potentially redirect to.

    Returns:
        flask.Response: A redirect response if the domain is "example.com",
                       or a 404 error response otherwise.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc  # Get the network location (domain)
        
        if not domain:
            # Handle cases where the URL is malformed or doesn't have a domain
            abort(400)  # Bad Request - URL is invalid

        if domain == "example.com":
            return redirect(url, code=302)  # Use 302 for temporary redirect
        else:
            abort(404)  # Not Found
    except Exception as e:
        # Handle potential parsing errors (e.g., invalid URL format)
        print(f"Error parsing URL: {e}")  # Log the error for debugging
        abort(400)  # Bad Request - URL is invalid


@app.route('/redirect')
def redirect_route():
    """
    Example route that uses the redirect_url function.
    Expects a 'url' query parameter.
    """
    url = request.args.get('url')
    if not url:
        return "Please provide a 'url' query parameter.", 400

    return redirect_url(url)


if __name__ == '__main__':
    from flask import request
    app.run(debug=True)

