import xml.etree.ElementTree as ET
from flask import Flask, request, abort
import defusedxml.ElementTree as DET

app = Flask(__name__)

# Maximum XML file size (in bytes) to prevent denial-of-service attacks
MAX_XML_SIZE = 100000  # Adjust as needed

@app.route('/xml_upload', methods=['POST'])
def XMLUpload():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    if 'xml_src' not in request.files:
        return "No xml_src file provided", 400

    xml_file = request.files['xml_src']

    # Check file size before reading
    xml_file.seek(0, 2)  # Go to the end of the file
    file_length = xml_file.tell()
    xml_file.seek(0)  # Go back to the beginning of the file

    if file_length > MAX_XML_SIZE:
        return "XML file too large", 413  # Request Entity Too Large

    try:
        xml_string = xml_file.read()

        # Use defusedxml to prevent XML vulnerabilities
        try:
            root = DET.fromstring(xml_string)
        except ET.ParseError as e:
            return f"XML Parsing Error: {e}", 400

        # Sanitize the XML data (example: remove potentially harmful attributes)
        # This is crucial to prevent XSS or other injection attacks.
        # The specific sanitization needed depends on the expected XML structure
        # and how the data will be used.  This is just an example.
        def sanitize_xml(element):
            for attribute in list(element.attrib):  # Iterate over a copy to allow deletion
                if attribute.lower() in ['onclick', 'onmouseover', 'style', 'src', 'href']:
                    del element.attrib[attribute]
            for child in element:
                sanitize_xml(child)

        sanitize_xml(root)

        # Convert the sanitized XML back to a string
        sanitized_xml_string = ET.tostring(root, encoding='utf8', method='xml').decode('utf8')

        return sanitized_xml_string, 200

    except Exception as e:
        print(f"Error processing XML: {e}")
        return "Error processing XML", 500


if __name__ == '__main__':
    app.run(debug=True)

