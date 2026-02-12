from flask import Flask, request, abort, jsonify
from lxml import etree
from lxml.etree import XMLSyntaxError

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

try:
    doc = etree.fromstring(xml)
except XMLSyntaxError as e:
    print(f"XML Syntax Error: {e}")
    doc = None  # Or handle the error appropriately, e.g., exit the application

@app.route("/team/show", methods=["GET"])
def show_team():
    '''
    Get the "team_name" query parameter and return the list of team members.
    @return: A JSON list of team members.
    '''
    team_name = request.args.get("team_name")

    if not team_name:
        return jsonify({"error": "team_name parameter is required"}), 400

    if doc is None:
        return jsonify({"error": "Failed to parse XML data"}), 500

    team = None
    for t in doc.xpath("//team"):
        if t.find("name").text == team_name:
            team = t
            break

    if not team:
        return jsonify({"error": f"Team '{team_name}' not found"}), 404

    members = []
    for member in team.xpath("./members/member"):
        members.append(member.find("name").text)

    return jsonify({"team_name": team_name, "members": members})


if __name__ == '__main__':
    app.run(debug=True)

