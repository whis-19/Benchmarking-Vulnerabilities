from lxml import etree
from io import StringIO
from django.http import HttpResponse
from django.utils.html import escape
import logging

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
        xpath_expression = request.GET.get('xpath', '')

        # Validate input data (stringent allowlist)
        if not isinstance(xml_data, str) or not isinstance(xpath_expression, str):
            return HttpResponse("Invalid input: XML and XPath must be strings.", status=400)

        # Sanitize XPath expression (very basic example, adapt to your needs)
        # This is crucial to prevent XPath injection.  A more robust solution
        # might involve parsing the XPath expression and validating its structure.
        # The following example only allows alphanumeric characters, underscores,
        # and forward slashes.  It's highly recommended to use a more sophisticated
        # validation approach based on your specific requirements.
        if not all(c.isalnum() or c in ['_', '/', '@', '[', ']', '=', '"'] for c in xpath_expression):
            return HttpResponse("Invalid XPath expression: Contains disallowed characters.", status=400)

        # XML Parsing with security measures
        parser = etree.XMLParser(
            no_network=True,  # Disable network access
            recover=True,      # Recover from errors
            remove_blank_text=True,
            resolve_entities=False, # Disable entity resolution
        )

        try:
            xml_tree = etree.parse(StringIO(xml_data), parser)
        except etree.XMLSyntaxError as e:
            logger.error(f"XML parsing error: {e}")
            return HttpResponse(f"Invalid XML: {escape(str(e))}", status=400)  # Escape for safe display

        # Execute XPath query
        try:
            results = xml_tree.xpath(xpath_expression)
            # Format the results as strings and escape them for safe display
            result_strings = [escape(str(result)) for result in results]
            response_data = ", ".join(result_strings)  # Join results with a comma
        except etree.XPathEvalError as e:
            logger.error(f"XPath evaluation error: {e}")
            return HttpResponse(f"Invalid XPath: {escape(str(e))}", status=400) # Escape for safe display

        # Set HTTP headers (including encoding)
        response = HttpResponse(response_data, content_type="text/plain; charset=utf-8")
        response['Content-Security-Policy'] = "default-src 'self'" # Example CSP
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'

        return response

    except Exception as e:
        logger.exception("An unexpected error occurred:")
        return HttpResponse(f"An unexpected error occurred: {escape(str(e))}", status=500) # Escape for safe display

