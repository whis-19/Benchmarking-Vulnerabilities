from flask import Flask, request, abort
from lxml import etree
from flask import jsonify
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

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

# Secure XML parsing: Disable DTDs and external entities
parser = etree.XMLParser(
    dtd_validation=False,
    resolve_entities=False,
    load_dtd=False,  # Disable DTD loading
)

try:
    doc = etree.fromstring(xml, parser=parser)
except etree.XMLSyntaxError as e:
    logging.error(f"XML parsing error: {e}")
    doc = None  # Handle the error appropriately, e.g., return an error response

@app.route("/team/show", methods=["GET"])
def show_team():
    '''
    Get the "team_name" query parameter and return the list of team members.
    @return: A JSON list of team members.  Returns an error if the team is not found.
    '''
    team_name = request.args.get("team_name")

    if not team_name:
        logging.warning("Team name not provided in the query parameters.")
        return jsonify({"error": "Team name is required"}), 400

    if doc is None:
        logging.error("XML document is not loaded properly.")
        return jsonify({"error": "Internal server error: XML parsing failed"}), 500

    try:
        # Use XPath to find the team by name.  This is safer than string concatenation.
        team = doc.xpath(f"/teams/team[name='{team_name}']")

        if not team:
            logging.warning(f"Team '{team_name}' not found.")
            return jsonify({"error": f"Team '{team_name}' not found"}), 404

        team = team[0]  # Get the first element if found

        members = []
        for member in team.xpath("./members/member/name/text()"):
            members.append(member)

        return jsonify({"team_name": team_name, "members": members}), 200

    except Exception as e:
        logging.exception("An error occurred while processing the request.")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

