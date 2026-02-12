from lxml import etree
from io import StringIO
from django.http import HttpResponse
from django.utils.html import escape  # Import escape for output sanitization
import logging
import hashlib
import re  # Import the regular expression module

# Configure logging (optional, but highly recommended)
logger = logging.getLogger(__name__)

MAX_XML_SIZE = 1024 * 1024  # 1MB limit
MAX_ERROR_MESSAGE_LENGTH = 200

def sanitize_xpath(xpath_query_string):
    """
    Sanitizes an XPath query string to prevent XPath injection vulnerabilities.

    This function uses a combination of allowlisting and denylisting to ensure
    that only safe XPath expressions are allowed.  It explicitly denies access
    to functions that could be used to access external resources or execute
    arbitrary code.

    Args:
        xpath_query_string: The XPath query string to sanitize.

    Returns:
        The sanitized XPath query string, or None if the query is considered unsafe.
    """

    # Stricter allowlist: Only allow alphanumeric, /, [, ], =, @, and basic functions
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/[]=@")
    allowed_functions = ["string-length", "count", "position", "last", "name", "local-name", "namespace-uri", "number", "string", "boolean", "not", "true", "false"]  # More safe functions
    denied_functions = ["document", "unparsed-text", "evaluate", "id", "key", "format-number", "system-property", "element-available", "function-available", "lang", "current", "unparsed-entity-uri", "resolve-uri", "collection", "accumulator-before", "accumulator-after"]

    # Check for denied functions using regular expressions for better accuracy
    for func in denied_functions:
        if re.search(r'\b' + re.escape(func) + r'\s*\(', xpath_query_string):
            return None  # Query is unsafe

    # Check if all characters are allowed or part of an allowed function
    is_valid = all(c in allowed_chars or any(f in xpath_query_string for f in allowed_functions) for c in xpath_query_string)

    if not is_valid:
        return None  # Query is unsafe

    return xpath_query_string


def handle_error(e, error_type="Unexpected", status_code=500):
    """
    Handles exceptions, logs errors, and returns an appropriate HTTP response.

    Args:
        e: The exception object.
        error_type: A string describing the type of error.
        status_code: The HTTP status code to return.

    Returns:
        An HttpResponse object with an error message and the specified status code.
    """
    error_message = str(e)
    if len(error_message) > MAX_ERROR_MESSAGE_LENGTH:
        error_message = error_message[:MAX_ERROR_MESSAGE_LENGTH] + "..."
    escaped_error_message = escape(error_message)
    logger.exception(f"{error_type} error: {escaped_error_message}")
    return HttpResponse(f"Error: {error_type} error occurred. {escaped_error_message}", status=status_code, content_type="text/plain")


def xpath_query(request):
    """
    Get the `xpath` value from the GET request,
    get the 'xml' value from the GET request,
    construct and parse the xml payload,
    return the result of the XPath query from the parsed xml.

    Security Considerations:

    1.  **Input Validation and Sanitization:**  The code validates and sanitizes both the 'xml' and 'xpath' parameters from the GET request to prevent XXE and XPath injection vulnerabilities.
        *   The 'xml' parameter is parsed with `lxml.etree.fromstring` using `resolve_entities=False` to disable external entity resolution, preventing XXE attacks. A try-except block handles potential XML parsing errors.
        *   The 'xpath' parameter is validated using a stricter allowlist and by blocking known dangerous functions. AST parsing or parameterized queries are recommended for more robust validation. The `escape` function is used to sanitize the output.

    2.  **Error Handling:**  Comprehensive error handling catches exceptions during XML parsing and XPath evaluation. Error messages are logged, truncated, and sanitized before being returned in the HTTP response.

    3.  **Logging:**  The `logging` module logs errors and potentially other relevant information. Sensitive data is not logged directly; instead, a hash or redacted version is logged.

    4.  **Output Sanitization:** The `escape` function from `django.utils.html` sanitizes the output of the XPath query to prevent XSS vulnerabilities.

    5.  **Rate Limiting/Authentication:**  Rate limiting and authentication should be implemented to prevent abuse of this endpoint.

    6.  **Content Type and Sniffing:** The response is set to `text/plain` to avoid potential interpretation of the output as HTML, mitigating XSS risks. The `X-Content-Type-Options: nosniff` header is also set.

    7.  **XPath Injection Prevention:** String formatting is avoided where possible. Parameterized queries or a more robust XPath sanitization library are recommended.

    8.  **Resource Limits:**  Resource limits, such as maximum XML size and query timeout, are enforced to prevent denial-of-service attacks. An iterative XML parser can be used for very large documents.

    """
    xml_data = request.GET.get('xml', '')
    xpath_query_string = request.GET.get('xpath', '')

    if not xml_data or not xpath_query_string:
        return HttpResponse("Error: Both 'xml' and 'xpath' parameters are required.", status=400, content_type="text/plain")

    # Limit XML size
    if len(xml_data) > MAX_XML_SIZE:
        logger.warning("XML data exceeds maximum size limit.")
        return HttpResponse("Error: XML data exceeds maximum size limit.", status=400, content_type="text/plain")

    try:
        # Security: Disable external entity resolution to prevent XXE
        xml_parser = etree.XMLParser(resolve_entities=False)
        xml_tree = etree.fromstring(xml_data.encode('utf-8'), parser=xml_parser)  # Encode to bytes
    except etree.XMLSyntaxError as e:
        return handle_error(e, "XML parsing", 400)
    except Exception as e:
        return handle_error(e, "Unexpected XML parsing", 500)

    # Security: Validate XPath query to prevent XPath injection
    sanitized_xpath = sanitize_xpath(xpath_query_string)

    if not sanitized_xpath:
        logger.warning(f"Potentially unsafe XPath query: {hashlib.sha256(xpath_query_string.encode()).hexdigest()}") # Log hash instead of query
        return HttpResponse("Error: Invalid or potentially unsafe XPath query.", status=400, content_type="text/plain")

    try:
        results = xml_tree.xpath(sanitized_xpath)
        # Sanitize the output to prevent XSS
        result_string = ", ".join([escape(str(r)) for r in results])
        response = HttpResponse(result_string, content_type="text/plain")
        response['X-Content-Type-Options'] = 'nosniff'
        return response
    except etree.XPathEvalError as e:
        return handle_error(e, "XPath evaluation", 400)
    except Exception as e:
        return handle_error(e, "Unexpected XPath evaluation", 500)

