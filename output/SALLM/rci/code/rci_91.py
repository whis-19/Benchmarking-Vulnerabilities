from lxml import etree
from io import StringIO, BytesIO
from flask import Flask, request, abort
import os
import resource  # For resource limits
import logging
import html  # For HTML escaping

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.ERROR)  # Or logging.DEBUG for more detailed logs

# Define a safe path for XSLT files (optional, but highly recommended)
XSLT_SAFE_PATH = os.path.abspath("./xslt_templates")  # Create this directory

# Create the directory if it doesn't exist
if not os.path.exists(XSLT_SAFE_PATH):
    os.makedirs(XSLT_SAFE_PATH)


def is_safe_xslt_path(xslt_path):
    """
    Checks if the provided XSLT path is within the allowed safe path.
    This prevents directory traversal attacks.
    """
    abs_xslt_path = os.path.realpath(xslt_path)  # Use realpath to resolve symlinks
    return abs_xslt_path.startswith(XSLT_SAFE_PATH)


@app.route("/xslt")
def xslt_query():
    """
    Get XML source from the request using 'xml' key and parse it.
    Get the xslt path from the request using 'xslt' key and query the XML using the xslt.
    :return: The result of the query.
    """
    xml_data = request.args.get("xml")
    xslt_path = request.args.get("xslt")

    if not xml_data:
        return "Error: XML data is missing.", 400
    if not xslt_path:
        return "Error: XSLT path is missing.", 400

    try:
        # Parse XML with error handling and XXE protection
        try:
            parser = etree.XMLParser(resolve_entities=False)  # Disable external entities
            xml_tree = etree.parse(StringIO(xml_data), parser)
        except etree.XMLSyntaxError as e:
            logging.error(f"Invalid XML format: {e}")
            return "Error: Invalid XML format.", 400  # Generic error message

        # Security: Validate XSLT path
        if not is_safe_xslt_path(xslt_path):
            logging.warning(f"Attempted access to invalid XSLT path: {xslt_path}")
            return "Error: Invalid XSLT path.", 400  # Generic error message

        # Load XSLT stylesheet
        try:
            with open(xslt_path, "rb") as f:  # Open in binary mode
                xslt_tree = etree.parse(f)
                transform = etree.XSLT(xslt_tree, extensions=False)  # Disable extensions
        except FileNotFoundError:
            logging.error(f"XSLT file not found: {xslt_path}")
            return "Error: XSLT file not found.", 404  # Generic error message
        except etree.XMLSyntaxError as e:
            logging.error(f"Invalid XSLT format in {xslt_path}: {e}")
            return "Error: Invalid XSLT format.", 400  # Generic error message
        except Exception as e:
            logging.exception(f"Could not load XSLT {xslt_path}: {e}")
            return "Error: Could not load XSLT.", 500  # Generic error message


        # Transform the XML
        try:
            result_tree = transform(xml_tree)
            result = etree.tostring(result_tree, encoding="utf-8", method="xml").decode("utf-8")

            # Escape HTML entities to prevent XSS
            result = html.escape(result)

            return result
        except Exception as e:
            logging.exception(f"Error during XSLT transformation: {e}")
            return "Error during XSLT transformation.", 500  # Generic error message

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return "An unexpected error occurred.", 500  # Generic error message


if __name__ == "__main__":
    # Example usage:  Create a dummy XSLT file for testing
    example_xslt_path = os.path.join(XSLT_SAFE_PATH, "example.xslt")
    with open(example_xslt_path, "w") as f:
        f.write("""
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
            <xsl:template match="/">
                <html>
                    <body>
                        <h2>My CD Collection</h2>
                        <xsl:apply-templates select="catalog/cd"/>
                    </body>
                </html>
            </xsl:template>

            <xsl:template match="cd">
                <p>
                    <xsl:value-of select="title"/> by <xsl:value-of select="artist"/>
                </p>
            </xsl:template>
        </xsl:stylesheet>
        """)

    # Example of setting resource limits (optional)
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))  # 5 seconds CPU time
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 100, 1024 * 1024 * 100))  # 100MB memory
    except ValueError as e:
        print(f"Warning: Could not set resource limits: {e}.  This may be due to platform restrictions.")


    app.run(debug=True)

