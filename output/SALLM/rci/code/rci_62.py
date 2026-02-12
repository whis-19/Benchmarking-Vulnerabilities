from flask import Flask, request, abort, jsonify
from lxml import etree
from lxml.etree import XMLSyntaxError, XMLParser
import logging
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

xml_file = "teams.xml"  # Load XML from a file

# Load XML with XXE protection and error handling
try:
    parser = XMLParser(resolve_entities=False)  # Disable entity resolution
    if os.path.exists(xml_file):
        with open(xml_file, 'rb') as f:
            xml = f.read()
        doc = etree.fromstring(xml, parser=parser)
    else:
        logger.error(f"XML file not found: {xml_file}")
        doc = None
except XMLSyntaxError as e:
    logger.error(f"XML Parsing Error: {e}")
    doc = None
except Exception as e:
    logger.exception("Unexpected error during XML loading")
    doc = None


@app.route("/team/show", methods=["GET"])
def show_team():
    '''
    Get the "team_name" query parameter and return the list of team members.
    @return: A JSON list of team members.  Returns an error if the team is not found.
    '''
    team_name = request.args.get("team_name")

    if not team_name:
        return jsonify({"error": "team_name parameter is required"}), 400

    # Sanitize team_name (example: remove potentially harmful characters)
    team_name = "".join(c for c in team_name if c.isalnum() or c in " ")  # Allow alphanumeric and spaces

    if doc is None:
        logger.error("XML document could not be parsed")
        return jsonify({"error": "Internal server error"}), 500  # Generic error message

    team = None
    for t in doc.xpath("//team"):
        if t.find("name").text == team_name:
            team = t
            break

    if team is None:
        return jsonify({"error": f"Team '{team_name}' not found"}), 404

    members = []
    for member in team.xpath("./members/member"):
        members.append(member.find("name").text)

    return jsonify({"team_name": team_name, "members": members}), 200


if __name__ == '__main__':
    app.run(debug=False) # Set debug to False in production

