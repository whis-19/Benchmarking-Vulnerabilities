from flask import Flask, request, jsonify
import defusedxml.ElementTree as ET  # Use defusedxml for XXE protection
import os
import re
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the path to the XML file.
XML_FILE_PATH = os.environ.get("XML_FILE_PATH", "users.xml")
ALLOWED_DIR = os.environ.get("ALLOWED_DIR", ".")  # Replace with the actual allowed directory, default to current directory

# Validate ALLOWED_DIR
if not os.path.isdir(ALLOWED_DIR):
    logging.error(f"ALLOWED_DIR '{ALLOWED_DIR}' does not exist.")
    exit()

# Normalize ALLOWED_DIR to ensure a trailing slash
ALLOWED_DIR = os.path.join(os.path.abspath(ALLOWED_DIR), '')  # Adds trailing slash if missing

# Validate the XML file path
abs_path = os.path.abspath(XML_FILE_PATH)
if not os.path.commonpath([ALLOWED_DIR]) == os.path.commonpath([ALLOWED_DIR, abs_path]):
    logging.error(f"Invalid XML file path: '{XML_FILE_PATH}' is outside the allowed directory '{ALLOWED_DIR}'.")
    exit()  # Or handle the error more gracefully

# Load the XML file once at application startup.
try:
    tree = ET.parse(XML_FILE_PATH)
    root = tree.getroot()
except FileNotFoundError:
    logging.error(f"Error: XML file not found at {XML_FILE_PATH}")
    root = None
except ET.ParseError as e:
    logging.error(f"Error parsing XML file '{XML_FILE_PATH}': {e}")
    root = None


@app.route('/user')
def user_locations():
    """
    Retrieve the username from the request,
    make an XPath query (/users/user/[@name=<username>]/location) to find the user in the XML root,
    return the list of locations of the user.
    """
    if root is None:
        return jsonify({"error": "XML file could not be loaded."}), 500

    username = request.args.get('username')

    if not username:
        return jsonify({"error": "Username is required."}), 400

    # Sanitize the username to prevent XML injection attacks.
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        return jsonify({"error": "Invalid username format.  Only alphanumeric characters, underscores, and hyphens are allowed."}), 400

    # Construct the XPath query using f-strings for readability, but ensure the username is properly sanitized.
    xpath_query = f"/users/user[@name='{username}']/location"

    try:
        locations = root.findall(xpath_query)
        location_list = [location.text for location in locations]
        return jsonify({"locations": location_list})
    except ET.ParseError as e:
        logging.error(f"Error parsing XML during XPath query: {e}")
        return jsonify({"error": "Error parsing XML during query."}), 500
    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full exception
        return jsonify({"error": "An unexpected error occurred."}), 500


if __name__ == '__main__':
    #  DO NOT USE debug=True IN PRODUCTION.  It can expose sensitive information.
    app.run(debug=False)

