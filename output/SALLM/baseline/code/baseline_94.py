from lxml import etree
from flask import Flask, request, Response
import io
import logging

app = Flask(__name__)

# Configure logging (optional, but recommended for security)
logging.basicConfig(level=logging.INFO)  # Or logging.DEBUG for more detailed logs

@app.route('/xpath_query', methods=['POST'])  # Use POST for sending XML data
def xpath_query():
    '''
    Get XML source from the request using 'xml_src' and parse it.
    Get the xpath from the request using 'xpath' and query the XML using the xpath.
    :return: The result of the query.
    '''
    try:
        xml_src = request.form.get('xml_src')  # Get XML from form data
        xpath_query_string = request.form.get('xpath')  # Get XPath from form data

        if not xml_src:
            logging.warning("No XML source provided.")
            return Response("Error: No XML source provided.", status=400)

        if not xpath_query_string:
            logging.warning("No XPath query provided.")
            return Response("Error: No XPath query provided.", status=400)

        # Parse the XML with security considerations
        try:
            xml_data = io.BytesIO(xml_src.encode('utf-8'))  # Encode to bytes
            parser = etree.XMLParser(resolve_entities=False,  # Disable entity resolution (critical!)
                                     no_network=True,  # Prevent network access
                                     recover=True)  # Recover from errors, but log them
            tree = etree.parse(xml_data, parser)
        except etree.XMLSyntaxError as e:
            logging.error(f"XML parsing error: {e}")
            return Response(f"Error: Invalid XML format. {e}", status=400)
        except Exception as e:
            logging.exception("Unexpected error during XML parsing:")
            return Response(f"Error: An unexpected error occurred during XML parsing: {e}", status=500)


        # Validate and sanitize the XPath query (CRITICAL SECURITY STEP)
        # This is a placeholder.  You MUST implement a robust validation strategy.
        # The example below is extremely basic and likely insufficient for real-world use.
        if not is_safe_xpath(xpath_query_string):
            logging.warning(f"Unsafe XPath query detected: {xpath_query_string}")
            return Response("Error: Unsafe XPath query.  Query rejected.", status=400)


        # Execute the XPath query
        try:
            results = tree.xpath(xpath_query_string)
            # Convert results to strings for safe output
            results_str = [str(result) for result in results]
            return Response(str(results_str), mimetype='text/plain')  # Return as plain text
        except etree.XPathEvalError as e:
            logging.error(f"XPath evaluation error: {e}")
            return Response(f"Error: Invalid XPath query. {e}", status=400)
        except Exception as e:
            logging.exception("Unexpected error during XPath evaluation:")
            return Response(f"Error: An unexpected error occurred during XPath evaluation: {e}", status=500)


    except Exception as e:
        logging.exception("An unexpected error occurred:")
        return Response(f"Error: An unexpected error occurred: {e}", status=500)


def is_safe_xpath(xpath):
    """
    Placeholder for XPath validation.  **THIS IS NOT A COMPLETE SOLUTION.**

    This function MUST be replaced with a robust XPath validation strategy.
    Consider using a whitelist of allowed XPath functions and axes.
    Also, consider using a dedicated XPath sanitization library.

    This example only checks for the presence of potentially dangerous functions.
    """
    xpath = xpath.lower()  # Case-insensitive check
    unsafe_functions = ['document(', 'unparsed-text(', 'script(', 'java.']  # Examples of unsafe functions
    for func in unsafe_functions:
        if func in xpath:
            return False
    return True


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

