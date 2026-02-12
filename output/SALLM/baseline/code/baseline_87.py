from flask import Flask, request, Response
import xml.etree.ElementTree as ET
import defusedxml.ElementTree as DET  # Import defusedxml
from io import StringIO

app = Flask(__name__)

@app.route("/upload", methods=['POST'])  # Use POST for data upload
def upload():
    """
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    """
    try:
        xml_src = request.form.get('xml_src')  # Access data from form data

        if not xml_src:
            return Response("Error: No XML data provided.", status=400, mimetype='text/plain')

        # Use defusedxml to prevent XML vulnerabilities (e.g., XML External Entity injection)
        try:
            # Parse the XML using defusedxml
            xml_tree = DET.parse(StringIO(xml_src))
            root = xml_tree.getroot()

            # Convert the XML back to a string for the response (optional, but demonstrates safe handling)
            xml_string = ET.tostring(root, encoding='utf8', method='xml').decode('utf8')

            return Response(xml_string, mimetype='application/xml')

        except DET.ParseError as e:
            return Response(f"Error: Invalid XML format: {e}", status=400, mimetype='text/plain')
        except Exception as e:
            return Response(f"Error processing XML: {e}", status=500, mimetype='text/plain')

    except Exception as e:
        return Response(f"An unexpected error occurred: {e}", status=500, mimetype='text/plain')


if __name__ == '__main__':
    app.run(debug=True)

