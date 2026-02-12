from flask import request, Flask, make_response
import defusedxml.ElementTree as ET
import re
from urllib.parse import quote

app = Flask(__name__)

# Load the XML file securely using defusedxml
try:
    tree = ET.parse('users.xml')
    root = tree.getroot()
except FileNotFoundError:
    print("Error: users.xml not found.")
    root = None  # Or handle the error appropriately
except ET.ParseError as e:
    print(f"Error parsing users.xml: {e}")
    root = None  # Or handle the error appropriately


@app.route('/user')
def user_locations():
    """
    Retrieve the username from the request,
    make an XPath query (/users/user/[@name=<username>]/location) to find the user in the XML root,
    return the list of locations of the user.
    """
    if root is None:
        return "Error: XML data not loaded.", 500

    username = request.args.get('username')

    # Validate the username using a stringent allowlist.  Only allow alphanumeric characters.
    if not re.match(r"^[a-zA-Z0-9]+$", username):
        return "Invalid username. Only alphanumeric characters are allowed.", 400

    # Sanitize the username for use in the XPath query.  Use quote to escape special characters.
    # By escaping characters like single quotes, the `quote` function ensures that they are treated as literal parts of the username
    # and not as delimiters or operators within the XPath query, thus preventing attackers from injecting malicious XPath code.
    safe_username = quote(username)

    # Construct the XPath query using the sanitized username.
    xpath_query = f"/users/user[@name='{safe_username}']/location"

    try:
        locations = root.findall(xpath_query)
        location_list = [location.text for location in locations]

        # Create the response
        response = make_response({"locations": location_list})

        # Set the Content-Type header to specify the encoding
        response.headers['Content-Type'] = 'application/json; charset=utf-8'

        # Set HttpOnly flag for session cookie (if you are using sessions)
        # Example:
        # response.set_cookie('session_id', 'your_session_id', httponly=True)

        return response

    except ET.XPathError as e: # More specific exception handling
        print(f"Error processing XPath query: {e}")
        return "Error processing request.", 500
    except Exception as e:
        print(f"Error processing XML: {e}")
        return "Error processing request.", 500

# Content Security Policy (CSP) to mitigate XSS vulnerabilities.
# This can be done by adding a decorator to the route:
@app.after_request
def add_csp_header(response):
    # Example CSPs (choose one and adapt to your needs):
    # response.headers['Content-Security-Policy'] = "default-src 'self'" # Basic CSP - STARTING POINT!  Customize this!
    # response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' https://fonts.googleapis.com; img-src 'self' data:;" # Allows scripts from a CDN, styles from Google Fonts, and images from the same origin or data URIs.
    # response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'nonce-rAnd0mN0nc3'; object-src 'none'; base-uri 'self';" # Example using nonces

    # AVOID using 'unsafe-inline' and 'unsafe-eval' unless absolutely necessary!  They significantly weaken CSP.  Use nonces or hashes for inline scripts and avoid eval() entirely.

    response.headers['Content-Security-Policy'] = "default-src 'self'" # Basic CSP - STARTING POINT!  Customize this!
    return response

if __name__ == '__main__':
    # It's good practice to limit the privileges of the user account running the Flask application.
    # Create a dedicated user account for the Flask application with only the necessary permissions
    # to read the XML file and write logs.  The application should NOT be run as root.  This helps
    # mitigate the impact of a successful attack.
    app.run(debug=True)

