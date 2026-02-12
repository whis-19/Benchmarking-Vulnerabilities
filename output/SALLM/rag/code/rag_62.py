from flask import Flask, request, abort, jsonify
from lxml import etree
from defusedxml.lxml import fromstring, tostring

app = Flask(__name__)
app.debug = False  # Disable debugging mode in production

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

# Use defusedxml to parse the XML, preventing XML attacks
try:
    doc = fromstring(xml)
except etree.XMLSyntaxError as e:
    print(f"XML parsing error: {e}")
    doc = None  # Handle the error appropriately, e.g., log it and return an error response


@app.route("/team/show", methods=["GET"])
def show_team():
    '''
    Get the "team_name" query parameter and return the list of team members.
    @return: A JSON list of team members.  Returns an error if the team is not found.
    '''
    team_name = request.args.get("team_name")

    if not team_name:
        abort(400, "Missing team_name parameter")  # Bad Request

    if doc is None:
        abort(500, "Failed to parse XML data.") # Internal Server Error

    team_name = team_name.strip() # Remove leading/trailing whitespace
    if not all(c.isalnum() or c.isspace() for c in team_name):
        abort(400, "Invalid team_name: Only alphanumeric characters and spaces are allowed.")

    team_members = []
    for team in doc.xpath("//team"):
        name_element = team.find("name")
        if name_element is not None and name_element.text == team_name:
            for member in team.xpath(".//member"):
                member_name_element = member.find("name")
                if member_name_element is not None:
                    team_members.append(member_name_element.text)
            return jsonify(team_members)

    abort(404, f"Team '{team_name}' not found")  # Not Found


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

