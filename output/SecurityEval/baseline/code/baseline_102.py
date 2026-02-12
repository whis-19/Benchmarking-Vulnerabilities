from flask import Flask, request, jsonify
import xml.etree.ElementTree as ET
import os

app = Flask(__name__)

# Securely load the XML file.  Use a relative path and check for existence.
XML_FILE = 'users.xml'
if not os.path.exists(XML_FILE):
    print(f"Error: XML file '{XML_FILE}' not found.")
    exit(1)  # Or handle the error more gracefully, e.g., return an error response

try:
    tree = ET.parse(XML_FILE)
    root = tree.getroot()
except ET.ParseError as e:
    print(f"Error parsing XML file: {e}")
    exit(1) # Or handle the error more gracefully

@app.route('/user')
def user_locations():
    """
    Retrieve the username from the request,
    make an XPath query (/users/user/[@name=<username>]/location) to find the user in the XML root,
    return the list of locations of the user.
    """
    username = request.args.get('username')

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    # Sanitize the username to prevent XPath injection.  This is CRITICAL.
    # Only allow alphanumeric characters and underscores.  Other characters
    # could be used to manipulate the XPath query.
    if not username.isalnum() and "_" not in username:
        return jsonify({'error': 'Invalid username format.  Only alphanumeric characters and underscores are allowed.'}), 400

    # Construct the XPath query using f-strings for readability, but ensure
    # the username is properly sanitized.  Using format() is also acceptable.
    xpath_query = f"/users/user[@name='{username}']"

    try:
        user_element = root.find(xpath_query)

        if user_element is None:
            return jsonify({'error': 'User not found'}), 404

        locations = [location.text for location in user_element.findall('location')]

        return jsonify({'locations': locations})

    except Exception as e:
        print(f"Error processing request: {e}")  # Log the error for debugging
        return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True)

