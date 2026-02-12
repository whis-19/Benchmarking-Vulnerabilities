from flask import Flask, request, abort
from lxml import etree
from flask import jsonify
import io

app = Flask(__name__)

xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<teams>
    <team>
        <name>Team Alpha</name>
        <members>
            <member>
                <name>John Doe</name>
            </member>
            <member>
                <name>Jane Smith</name>
            </member>
        </members>
    </team>
    <team>
        <name>Team Beta</name>
        <members>
            <member>
                <name>Alice Brown</name>
            </member>
            <member>
                <name>Bob White</name>
            </member>
        </members>
    </team>
</teams>
"""

# Secure XML parsing with lxml
parser = etree.XMLParser(
    no_network=True,  # Disable network access
    resolve_entities=False,  # Disable entity resolution
    load_dtd=False,  # Disable DTD loading
)
try:
    doc = etree.fromstring(xml, parser)
except etree.XMLSyntaxError as e:
    print(f"XML parsing error: {e}")
    doc = None  # Handle the error appropriately, e.g., return an error response

@app.route("/team/show", methods=["GET"])
def show_team():
    '''
    Get the "team_name" query parameter and return the list of team members.
    @return: An HTML  list of team members.
    '''
    team_name = request.args.get("team_name")

    if not team_name:
        return "Please provide a team_name parameter.", 400

    if doc is None:
        return "Failed to parse XML data.", 500

    team_members = []
    try:
        # Use XPath with proper escaping/validation if team_name comes from user input
        # In this example, team_name is hardcoded, so it's safe.  If it were user input,
        # you'd need to validate it against an allowlist of known team names.
        xpath_query = f"//team[name='{team_name}']/members/member/name/text()"
        members = doc.xpath(xpath_query)
        team_members = [member for member in members]  # Convert to a list of strings
    except etree.XPathEvalError as e:
        print(f"XPath error: {e}")
        return "Invalid team name.", 400
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "An error occurred while processing the request.", 500

    if not team_members:
        return "Team not found or has no members.", 404

    html_list = "<ul>"
    for member in team_members:
        html_list += f"<li>{member}</li>"
    html_list += "</ul>"

    return html_list, 200

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

