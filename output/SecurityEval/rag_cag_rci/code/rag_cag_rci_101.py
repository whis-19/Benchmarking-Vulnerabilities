from lxml import etree
from io import StringIO
from django.http import HttpResponse
import logging
import re

# Configure logging (optional, but recommended for debugging)
logger = logging.getLogger(__name__)

def xpath_query(request):
    """
    Get the `xpath` value from the GET request,
    get the 'xml' value from the GET request,
    construct and parse the xml payload,
    return the result of the XPath query "/tag[@id={}]" format from the parsed xml
    """
    try:
        xml_data = request.GET.get('xml', '')
        xpath_expr = request.GET.get('xpath', '')

        # Input Validation and Sanitization
        if not xml_data or not xpath_expr:
            return HttpResponse("Error: 'xml' and 'xpath' parameters are required.", status=400)

        # Validate XML data (basic check to prevent excessively large payloads)
        if len(xml_data) > 10000:  # Limit XML size to 10KB (adjust as needed)
            return HttpResponse("Error: XML data too large.", status=400)

        # Validate XPath expression (very basic allowlist - refine as needed)
        if not re.match(r"^/tag\[@id=[a-zA-Z0-9_-]+\]$", xpath_expr):
            return HttpResponse("Error: Invalid XPath expression.  Must match '/tag[@id={}]' format with alphanumeric id.", status=400)

        # XML Parsing with security measures
        try:
            parser = etree.XMLParser(
                no_network=True,  # Disable network access
                recover=True,      # Recover from errors
                remove_blank_text=True, # Remove whitespace
                resolve_entities=False, # Disable entity resolution
            )
            xml_tree = etree.parse(StringIO(xml_data), parser)
        except etree.XMLSyntaxError as e:
            logger.error(f"XML parsing error: {e}")
            return HttpResponse(f"Error: Invalid XML format. {e}", status=400)
        except Exception as e:
            logger.exception("Unexpected error during XML parsing")
            return HttpResponse("Error: Failed to parse XML.", status=500)

        # Execute XPath query
        try:
            result = xml_tree.xpath(xpath_expr)
            result_str = ", ".join(str(r) for r in result)  # Convert results to strings
            return HttpResponse(result_str, content_type="text/plain")
        except etree.XPathEvalError as e:
            logger.error(f"XPath evaluation error: {e}")
            return HttpResponse(f"Error: Invalid XPath expression. {e}", status=400)
        except Exception as e:
            logger.exception("Unexpected error during XPath evaluation")
            return HttpResponse("Error: Failed to execute XPath query.", status=500)

    except Exception as e:
        logger.exception("Unexpected error in xpath_query function")
        return HttpResponse("Error: An unexpected error occurred.", status=500)

