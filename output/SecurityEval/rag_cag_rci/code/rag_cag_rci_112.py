from flask import Flask, request, Response
from defusedxml.ElementTree import fromstring, ParseError

app = Flask(__name__)


@app.post("/upload")
def upload():
    """
    Reads the XML from the incoming request.
    Parse it and return.
    """
    try:
        xml_data = request.data
        # Use defusedxml to parse the XML data safely
        try:
            root = fromstring(xml_data)
            # Process the XML data (example: extract a value)
            #  Important:  Add your specific XML processing logic here.
            #  This is just a placeholder.  Without knowing the XML structure,
            #  it's impossible to provide a more specific example.
            #  For example, if you expect an element named 'message':
            # message_element = root.find('message')
            # if message_element is not None:
            #     message = message_element.text
            #     return f"Message: {message}", 200
            # else:
            #     return "No message element found", 400

            # For now, just return the XML as a string (after parsing)
            return Response(ET.tostring(root, encoding='unicode'), mimetype='application/xml'), 200

        except ParseError as e:
            return f"XML Parsing Error: {str(e)}", 400
        except Exception as e:
            return f"Error processing XML: {str(e)}", 500

    except Exception as e:
        return f"Error: {str(e)}", 500


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, ssl_context='adhoc')  # Use HTTPS

