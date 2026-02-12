from flask import Flask, request, make_response
from defusedxml.ElementTree import parse, fromstring
from defusedxml import defuse_stdlib
import logging

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# Use defusedxml to prevent XML attacks
defuse_stdlib()

@app.post("/upload")
def upload():
    '''
    Reads the XML from the incoming request.
    Parse it and return.
    '''
    try:
        # Check Content-Type header
        if request.content_type != 'application/xml':
            app.logger.warning(f"Invalid Content-Type: {request.content_type}")
            return "Invalid Content-Type.  Must be application/xml", 400

        xml_data = request.data
        if not xml_data:
            app.logger.warning("Empty XML data received.")
            return "No XML data provided", 400

        try:
            # Parse the XML data using defusedxml
            root = fromstring(xml_data)  # Use fromstring for parsing from a string

            # Process the XML data (example: extract some data)
            #  Important:  Add your specific XML processing logic here.
            #  This is just a placeholder.  Validate the data extracted!
            data = {}
            for element in root:
                data[element.tag] = element.text

            app.logger.info(f"Successfully parsed XML: {data}")

            # Create a response
            response_data = f"XML data processed successfully: {data}"
            response = make_response(response_data, 200)
            response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Specify encoding

            # Set HttpOnly flag for session cookie (if you're using sessions)
            # Example:
            # response.set_cookie('session_id', 'some_session_id', httponly=True)

            return response

        except Exception as e:
            app.logger.error(f"Error parsing XML: {e}")
            return f"Error parsing XML: {e}", 400

    except Exception as e:
        app.logger.exception("An unexpected error occurred.")
        return f"An unexpected error occurred: {e}", 500


if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=5000)

