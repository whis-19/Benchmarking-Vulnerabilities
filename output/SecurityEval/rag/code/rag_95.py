from flask import Flask, request, Response
import lxml.etree
from lxml import etree
from io import StringIO, BytesIO

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store'  # Prevent caching sensitive data
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.post("/upload")
def upload():
    """
    Get the xml_src from the request, parse it and return it as string.
    Securely parses XML to prevent XXE and other vulnerabilities.
    """
    xml_src = request.data  # Get raw data, not form data

    if not xml_src:
        return "No XML data provided", 400

    try:
        # Use lxml with secure parsing options
        parser = etree.XMLParser(
            no_network=True,  # Disable network access
            recover=False,  # Do not try to recover from errors
            remove_blank_text=True, # Remove insignificant whitespace
            resolve_entities=False, # Disable entity resolution
        )

        # Parse the XML data from bytes
        try:
            xml_tree = etree.parse(BytesIO(xml_src), parser)
        except etree.XMLSyntaxError as e:
            return f"XML Parsing Error: {str(e)}", 400

        # Serialize the XML tree back to a string
        xml_string = etree.tostring(xml_tree, encoding="utf-8").decode("utf-8")

        return Response(xml_string, mimetype='application/xml')

    except Exception as e:
        print(f"An unexpected error occurred: {e}")  # Log the error
        return "An error occurred during XML processing.", 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

