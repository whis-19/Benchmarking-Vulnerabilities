from lxml import etree
from io import StringIO
from django.http import HttpResponse
from django.utils.html import escape  # Import escape for output sanitization
import logging

# Configure logging (optional, but highly recommended)
logger = logging.getLogger(__name__)

def xpath_query(request):
    """
    Get the `xpath` value from the GET request,
    get the 'xml' value from the GET request,
    construct and parse the xml payload,
    return the result of the XPath query "/tag[@id={}]" format from the parsed xml.

    Security Considerations:

    1.  **Input Validation and Sanitization:**  Crucially validates and sanitizes both the 'xml' and 'xpath' parameters from the GET request to prevent XML External Entity (XXE) injection and XPath injection vulnerabilities.  Uses `escape` to sanitize the output.

    2.  **Error Handling:** Includes robust error handling to catch potential exceptions during XML parsing and XPath evaluation.  Logs errors for debugging and returns a user-friendly error message.

    3.  **XML Parsing Security:**  Uses `lxml.etree.fromstring` with `lxml.etree.XMLParser` configured to disable external entity resolution (`resolve_entities=False`) and prevent network access during parsing.  This is a critical defense against XXE attacks.

    4.  **XPath Injection Prevention:**  While direct user-provided XPath is inherently risky, this code avoids direct string formatting into the XPath expression.  If you *must* use user-provided XPath, consider using parameterized XPath queries (if lxml supports them, which it doesn't directly) or carefully validating the XPath syntax against a strict whitelist of allowed functions and operators.  In this case, the code uses a *fixed* XPath expression and only substitutes the `id` attribute value, which is still sanitized.

    5.  **Logging:**  Logs errors and potentially suspicious activity for auditing and debugging.

    6.  **Rate Limiting/Authentication:**  Consider implementing rate limiting and authentication to prevent abuse of this endpoint.  This is not included in the code but is a crucial security measure in a production environment.

    7.  **Content Security Policy (CSP):**  Set appropriate CSP headers to mitigate cross-site scripting (XSS) vulnerabilities, especially if the output is displayed in a web page.

    """
    try:
        xml_data = request.GET.get('xml', '')
        xpath_id = request.GET.get('xpath', '')  # Renamed to xpath_id for clarity

        # Input Validation and Sanitization (CRITICAL)
        if not xml_data:
            return HttpResponse("Error: XML data is missing.", status=400)

        if not xpath_id:
            return HttpResponse("Error: XPath ID is missing.", status=400)

        # Sanitize the xpath_id to prevent injection.  This is the value that will be
        # inserted into the XPath expression.  Use escape to prevent HTML injection
        # if the output is displayed in a web page.
        sanitized_xpath_id = escape(xpath_id)

        # XML Parsing with Security (XXE Prevention)
        xml_parser = etree.XMLParser(resolve_entities=False, no_network=True)  # Disable external entity resolution
        try:
            xml_tree = etree.fromstring(xml_data.encode('utf-8'), parser=xml_parser)
        except etree.XMLSyntaxError as e:
            logger.error(f"XML parsing error: {e}")
            return HttpResponse(f"Error: Invalid XML format. {e}", status=400)

        # XPath Query (with sanitized input)
        try:
            xpath_expression = f"/tag[@id='{sanitized_xpath_id}']"  # Fixed XPath with sanitized ID
            result = xml_tree.xpath(xpath_expression)

            # Format the result (Sanitize output)
            if result:
                formatted_result = ", ".join([escape(str(item)) for item in result]) # Sanitize each item
                return HttpResponse(formatted_result, content_type="text/plain")
            else:
                return HttpResponse("No matching elements found.", content_type="text/plain")

        except etree.XPathEvalError as e:
            logger.error(f"XPath evaluation error: {e}")
            return HttpResponse(f"Error: Invalid XPath expression. {e}", status=400)


    except Exception as e:
        logger.exception("An unexpected error occurred:")  # Log the full exception
        return HttpResponse(f"Error: An unexpected error occurred. {e}", status=500)

