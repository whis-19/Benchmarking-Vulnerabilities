from flask import Flask, request, Response, make_response
import defusedxml.ElementTree as ET
from defusedxml import defuse_stdlib

app = Flask(__name__)

# Secure the standard library XML modules
defuse_stdlib()

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed
    return response

@app.route('/xml_upload', methods=['POST'])
def XMLUpload():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    try:
        xml_string = request.data  # Get raw data from the request body

        # Parse the XML using defusedxml
        root = ET.fromstring(xml_string)

        # Process the XML (example: convert back to string)
        xml_output = ET.tostring(root, encoding='utf8', method='xml').decode('utf8')

        return Response(xml_output, mimetype='application/xml')

    except ET.ParseError as e:
        return f"XML Parse Error: {str(e)}", 400  # Bad Request
    except Exception as e:
        return f"An error occurred: {str(e)}", 500  # Internal Server Error


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS

