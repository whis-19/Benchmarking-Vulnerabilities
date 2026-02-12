"""
Security Review of Flask Application
"""

from flask import Flask, request, jsonify, make_response
from defusedxml.lxml import fromstring, parse  # Use defusedxml
import html
import os

app = Flask(__name__)
app.debug = False  # Disable debugging mode in production

# Input validation function
def is_valid_xml(xml_string):
    try:
        # Use defusedxml to parse the XML
        # defusedxml is preferred over lxml, even with parser options set, because
        # it provides a more comprehensive defense by disabling dangerous features
        # at a lower level.  This makes it less likely that a vulnerability could
        # be exploited due to a misconfiguration or a bug in lxml.
        fromstring(xml_string)
        return True
    except Exception:
        return False

@app.route('/process_xml', methods=['POST'])
def process_xml():
    xml = request.data.decode('utf-8')

    if not is_valid_xml(xml):
        return jsonify({"error": "Invalid XML"}), 400

    try:
        # Use defusedxml to parse the XML from a string
        doc = fromstring(xml)

        # Extract team name and members
        team_name = doc.findtext('team/name')
        members = [member.text for member in doc.findall('team/members/member')]

        # Input validation:  Strict allowlist for team_name
        # Ideally, use a predefined list of allowed team names for maximum security.
        # Example: allowed_teams = ["Team Alpha", "Team Beta", "Team Gamma"]
        # if team_name not in allowed_teams:
        #     return jsonify({"error": "Invalid team_name.  Team name not allowed."}), 400
        #
        # For demonstration purposes, we're using a less strict check:
        if not all(c.isalnum() or c.isspace() for c in team_name):
            return jsonify({"error": "Invalid team_name.  Only alphanumeric characters and spaces are allowed."}), 400

        # Process the data (e.g., store in a database)
        # In this example, we'll just return the data as an HTML list

        html_list = "<ul>"
        for member in members:
            html_list += f"<li>{html.escape(member)}</li>"  # Escape HTML special characters
        html_list += "</ul>"

        # Explanation:  Even though we have input validation, it's best practice to
        # always escape HTML special characters when constructing HTML from
        # user-provided data to prevent XSS vulnerabilities.

        response = make_response(html_list)
        response.headers['Content-Type'] = 'text/html'
        return response

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Example of using defusedxml.lxml.parse to parse XML from a file
# @app.route('/process_xml_file', methods=['POST'])
# def process_xml_file():
#     if 'xml_file' not in request.files:
#         return jsonify({"error": "No file part"}), 400
#     file = request.files['xml_file']
#     if file.filename == '':
#         return jsonify({"error": "No selected file"}), 400
#     try:
#         # Use parse to parse XML from a file
#         doc = parse(file, parser)
#         # Process the XML document
#         return jsonify({"message": "XML file processed successfully"})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # DO NOT USE THIS IN PRODUCTION
    # Use a production WSGI server like Gunicorn or uWSGI
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

