import lxml.etree
from flask import Flask, request, abort
import io
import logging
import signal  # For timeout
import uuid  # For request IDs

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Maximum request size (1MB) - adjust as needed
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

# Maximum parsing time (seconds)
MAX_PARSING_TIME = 10

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("XML parsing timed out")

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    request_id = str(uuid.uuid4())  # Generate a unique request ID
    logger = logging.getLogger(request_id)  # Create a logger specific to this request
    logger.setLevel(logging.INFO)  # Set the logging level for this logger

    try:
        # Validate Content-Type
        content_type = request.headers.get('Content-Type', '').strip().lower()
        if content_type not in ('application/xml', 'text/xml'):
            logger.warning(f"[{request_id}] Invalid Content-Type: {content_type}")
            return "Error: Content-Type must be application/xml or text/xml", 415

        xml_src = request.data  # Get raw XML data from the request body

        # Check if XML data is empty
        if not xml_src:
            logger.warning(f"[{request_id}] Empty XML data received.")
            return "Error: No XML data provided.", 400

        # Use a try-except block to catch potential parsing errors
        try:
            # Set up a timeout
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(MAX_PARSING_TIME)

            # Parse the XML with security measures:
            # 1. Disable DTD processing to prevent XXE attacks.
            # 2. Disable external entity loading.
            parser = lxml.etree.XMLParser(
                dtd_validation=False,  # Disable DTD validation
                resolve_entities=False,  # Disable external entity resolution
                no_network=True, # Prevent network access
                recover=True # Attempt to recover from errors
            )
            parser.error_log = lxml.etree.ErrorLog()

            # Parse the XML from the string using io.BytesIO to handle byte strings
            xml_tree = lxml.etree.parse(io.BytesIO(xml_src), parser)

            # Serialize the XML tree back to a string.  Important to use encoding='utf-8'
            # to ensure consistent output.  Also, use xml_declaration=True to include the XML declaration.
            xml_string = lxml.etree.tostring(xml_tree, encoding='utf-8', xml_declaration=True).decode('utf-8')

            logger.info(f"[{request_id}] XML parsed successfully.")
            return xml_string, 200

        except lxml.etree.XMLSyntaxError as e:
            logger.error(f"[{request_id}] Invalid XML format: {str(e)}")
            return f"Error: Invalid XML format. {str(e)}", 400
        except TimeoutException as e:
            logger.error(f"[{request_id}] XML parsing timed out: {str(e)}")
            return "Error: XML parsing timed out", 408  # Request Timeout
        except Exception as e:
            logger.exception(f"[{request_id}] An unexpected error occurred during XML parsing.") # Log the full exception
            return f"Error: An unexpected error occurred during XML parsing. {str(e)}", 500
        finally:
            signal.alarm(0)  # Disable the alarm
            for error in parser.error_log:
                logger.warning(f"[{request_id}] XML Parsing Recovery: {error}")


    except Exception as e:
        logger.exception(f"[{request_id}] An error occurred processing the request.") # Log the full exception
        return f"Error: An error occurred processing the request. {str(e)}", 500


if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

