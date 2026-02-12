from flask import request, Flask, make_response
import re
from urllib.parse import urlparse
import html

app = Flask(__name__)

# Set the session cookie to HttpOnly
app.config['SESSION_COOKIE_HTTPONLY'] = True

@app.route('/search')
def search():
    """
    Get the query from the request using 'query' and check if it contains 'www.example.com/' or 'beta.example.com/'.
    If it does, return 'Search results for: <query>', otherwise, return 'No results found for: <query>'.
    """
    query = request.args.get('query', '')

    # Input validation:  Strict allowlist for query characters.  Allow alphanumeric, spaces, and a few common symbols.
    if not re.match(r"^[a-zA-Z0-9\s\.,?!-]+$", query):
        return "Invalid query.  Please use only alphanumeric characters, spaces, and common punctuation.", 400

    # URL parsing and validation
    try:
        parsed_url = urlparse(query)
        hostname = parsed_url.hostname
    except:
        hostname = None

    if hostname:
        # Handle arbitrary subdomain sequences correctly and escape metacharacters
        if re.search(r"^(www\.)?example\.com$", hostname) or re.search(r"^(beta\.)?example\.com$", hostname):
            # Escape the query for HTML output to prevent XSS
            escaped_query = html.escape(query)
            result = f"Search results for: {escaped_query}"
        else:
            escaped_query = html.escape(query)
            result = f"No results found for: {escaped_query}"
    else:
        escaped_query = html.escape(query)
        result = f"No results found for: {escaped_query}"

    # Set the content type to prevent MIME sniffing vulnerabilities
    response = make_response(result)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    return response

if __name__ == '__main__':
    app.run(debug=False)

