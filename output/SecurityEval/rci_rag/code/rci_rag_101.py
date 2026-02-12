from lxml import etree
from io import StringIO
from django.http import HttpResponse
from django.utils.html import escape
import logging
import re
from django.middleware.csrf import get_token

# Configure logging
logger = logging.getLogger(__name__)

# Define a set of allowed XPath queries.  This is the preferred approach.
ALLOWED_XPATH_QUERIES = {
    "get_all_tags": "//tag",
    "get_tag_by_id": "//tag[@id=$id]",  # Example of a parameterized query (not directly supported by lxml)
    # Add more allowed queries here
}


def xpath_query(request):
    """
    Get the `xpath` value from the GET request,
    get the 'xml' value from the GET request,
    construct and parse the xml payload,
    return the result of the XPath query "/tag[@id={}]" format from the parsed xml
    """
    try:
        # Validate request method
        if request.method != 'GET':
            return HttpResponse("Invalid request method. Only GET is allowed.", status=405)

        # Get parameters from GET request
        xpath_expression = request.GET.get('xpath', '')
        xml_data = request.GET.get('xml', '')

        # ---  PREFERRED APPROACH: Use a predefined set of XPath queries ---
        if xpath_expression not in ALLOWED_XPATH_QUERIES:
            logger.warning(f"Invalid XPath query requested: {xpath_expression}")
            return HttpResponse("Invalid XPath query.", status=400)

        # --- ALTERNATIVE (LESS SECURE) APPROACH: Validate user-provided XPath ---
        # if not isinstance(xpath_expression, str):
        #     logger.warning(f"Invalid xpath expression type: {type(xpath_expression)}")
        #     return HttpResponse("Invalid xpath expression. Must be a string.", status=400)

        # if len(xpath_expression) > 256:
        #     logger.warning(f"XPath expression too long: {len(xpath_expression)}")
        #     return HttpResponse("XPath expression is too long.", status=400)

        # if not re.match(r"^[a-zA-Z0-9/@\[\]=]+$", xpath_expression):
        #     logger.warning(f"Invalid xpath expression: {xpath_expression}")
        #     return HttpResponse("Invalid xpath expression.  Only alphanumeric characters and '/', '@', '[', ']', '=' are allowed.", status=400)


        if not isinstance(xml_data, str):
            logger.warning(f"Invalid xml data type: {type(xml_data)}")
            return HttpResponse("Invalid xml data.  Must be a string.", status=400)

        if len(xml_data) > 10240:  # Example: 10KB limit
            logger.warning(f"XML data too large: {len(xml_data)}")
            return HttpResponse("XML data is too large.", status=400)


        # XML parsing with security measures
        try:
            parser = etree.XMLParser(
                no_network=True,  # Disable network access
                recover=False,    # Do not try to recover from errors
                remove_blank_text=True, # Remove blank text nodes
                remove_comments=True,   # Remove comments
                remove_pis=True,        # Remove processing instructions
            )
            xml_tree = etree.parse(StringIO(xml_data), parser)
        except etree.XMLSyntaxError:
            logger.exception("XML parsing error")
            return HttpResponse("Invalid XML format.", status=400)  # Generic error message
        except Exception:
            logger.exception("Unexpected error during XML parsing")
            return HttpResponse("Error parsing XML.", status=500) # Generic error message

        # Execute XPath query
        try:
            # ---  PREFERRED APPROACH: Use a predefined set of XPath queries ---
            xpath_to_execute = ALLOWED_XPATH_QUERIES[xpath_expression]
            results = xml_tree.xpath(xpath_to_execute)  # No user-provided XPath here!

            # --- ALTERNATIVE (LESS SECURE) APPROACH: Execute validated XPath ---
            # results = xml_tree.xpath(xpath_expression)

            result_string = ", ".join(str(r) for r in results)  # Convert results to strings
        except etree.XPathEvalError:
            logger.exception("XPath evaluation error")
            return HttpResponse("Invalid XPath expression.", status=400) # Generic error message
        except Exception:
            logger.exception("Unexpected error during XPath evaluation")
            return HttpResponse("Error evaluating XPath.", status=500) # Generic error message

        # Sanitize output (escape HTML)
        sanitized_result = escape(result_string)

        # Set HTTP headers (including encoding)
        response = HttpResponse(sanitized_result, content_type="text/plain; charset=utf-8")
        response['Content-Security-Policy'] = "default-src 'self'"

        # Add CSRF protection (even for GET requests)
        get_token(request)  # Ensure CSRF token is set in the cookie

        # Set HttpOnly flag for session cookie (if sessions are used)
        # request.session.set_expiry(0)  # Example: Set session expiry
        # response.set_cookie('sessionid', request.session.session_key, httponly=True) # Example: Set HttpOnly flag

        return response

    except Exception:
        logger.exception("Unexpected error in xpath_query view")
        return HttpResponse("An unexpected error occurred.", status=500) # Generic error message

