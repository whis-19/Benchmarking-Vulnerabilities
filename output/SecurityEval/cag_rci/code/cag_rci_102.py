from flask import Flask, request, jsonify
import xml.etree.ElementTree as ET
import os
from defusedxml import ElementTree as DET  # Import defusedxml
import re  # For regular expressions
from lxml import etree  # For safer XPath (pip install lxml)
import logging  # For logging errors
import secrets  # For generating secure tokens (if authentication is added)

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Load the XML file securely using defusedxml
try:
    # IMPORTANT: Ensure 'users.xml' has appropriate file permissions (e.g., chmod 600)
    tree = DET.parse('users.xml')  # Use defusedxml to parse
    root = tree.getroot()
except FileNotFoundError:
    logging.error("users.xml not found.")
    root = None  # Handle the case where the file doesn't exist
except ET.ParseError as e:
    logging.error(f"Error parsing XML: {e}")
    root = None  # Handle XML parsing errors


@app.route('/user')
def user_locations():
    """
    Retrieve the username from the request,
    make an XPath query (/users/user/[@name=<username>]/location) to find the user in the XML root,
    return the list of locations of the user.
    """
    if root is None:
        return jsonify({"error": "XML data not available"}), 500

    username = request.args.get('username')

    # Input validation: Check if username is provided and is a string
    if not username or not isinstance(username, str):
        return jsonify({"error": "Invalid username provided"}), 400

    # Sanitize the username (more robust) - See OWASP Input Validation Cheat Sheet
    # https://owasp.org/www-project-cheat-sheets/
    username = username.strip()  # Remove leading/trailing whitespace
    if not username:
        return jsonify({"error": "Username cannot be empty"}), 400

    # Validate username format (example: alphanumeric and underscores only)
    # Use a whitelist approach for allowed characters
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return jsonify({"error": "Invalid username format"}), 400

    # Limit username length
    if len(username) > 50:
        return jsonify({"error": "Username too long"}), 400

    if len(username) < 6:
        return jsonify({"error": "Username too short"}), 400

    # Use lxml for safer XPath (still requires caution - XPath injection possible!)
    try:
        # Convert root to lxml element
        root_lxml = etree.fromstring(ET.tostring(root))

        # Use parameterized query with lxml (still requires caution - XPath injection possible!)
        xpath_query = "/users/user[@name=$username]/location"
        locations = root_lxml.xpath(xpath_query, username=username)

        location_list = [location.text for location in locations]

        # Simulate authentication (replace with a real authentication system)
        # In a real system, you'd verify the user's credentials before proceeding.
        # Passwords should be hashed and salted before storage to prevent them from being compromised in case of a data breach.
        # This is just a placeholder.
        # if authenticate_user(username, password):  # Replace with actual authentication
        #     return jsonify({"locations": location_list})
        # else:
        #     return jsonify({"error": "Authentication failed"}), 401

        # For now, just return the locations (after proper input validation)
        return jsonify({"locations": location_list})

    # Example of iterating through the XML tree (alternative to XPath)
    # for user_element in root.findall('user'):
    #     if user_element.get('name') == username:
    #         locations = [loc.text for loc in user_element.findall('location')]
    #         return jsonify({"locations": locations})

    except etree.XPathEvalError as e:
        logging.error(f"XPath error: {e}")
        return jsonify({"error": "Invalid username"}), 400  # Generic error
    except Exception as e:
        logging.exception("An unexpected error occurred")  # Log the full exception
        return jsonify({"error": "An unexpected error occurred"}), 500


if __name__ == '__main__':
    # Ensure HTTPS is used in production (not shown here, requires SSL certificate setup)
    # Also, consider using Flask-Talisman to enforce HTTPS and enable HSTS
    # from flask_talisman import Talisman
    # talisman = Talisman(app, force_https=True, hsts_max_age=31536000, hsts_include_subdomains=True, hsts_preload=True)

    # Consider using Flask-Limiter to prevent brute-force attacks and username enumeration
    # from flask_limiter import Limiter
    # from flask_limiter.util import get_remote_address

    # limiter = Limiter(
    #     app,
    #     key_func=get_remote_address,
    #     default_limits=["200 per day", "50 per hour"]
    # )

    # @app.route('/user')
    # @limiter.limit("10 per minute")  # Example rate limit
    # def user_locations():

    # NEVER run in debug mode in production!  It exposes sensitive information and allows arbitrary code execution.
    app.run(debug=False) # For development without HTTPS, NEVER TRUE IN PRODUCTION

