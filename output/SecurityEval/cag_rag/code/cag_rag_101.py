from lxml import etree
from io import StringIO
from django.http import HttpResponse
from django.utils.html import escape

def xpath_query(request):
    '''
    Get the `xpath` value from the GET request,
    get the 'xml' value from the GET request,
    construct and parse the xml payload,
    return the result of the XPath query "/tag[@id={}]" format from the parsed xml
    '''
    xpath_expression = request.GET.get('xpath', '')
    xml_data = request.GET.get('xml', '')

    # Input validation:  Strict allowlist for xpath and xml.  This is crucial.
    # Adjust the allowlists based on the expected structure of your XML and XPath.
    # This example is very restrictive and should be expanded as needed, but always with caution.
    if not is_valid_xpath(xpath_expression):
        return HttpResponse("Invalid XPath expression", status=400)

    if not is_valid_xml(xml_data):
        return HttpResponse("Invalid XML data", status=400)

    try:
        # Use defusedxml-style parsing to prevent XXE and other vulnerabilities.
        parser = etree.XMLParser(
            no_network=True,  # Disables network access
            resolve_entities=False, # Disable entity resolution
            load_dtd=False, # disable DTD loading
        )
        xml_tree = etree.parse(StringIO(xml_data), parser)

        # Execute the XPath query.  Even with input validation, be careful.
        try:
            results = xml_tree.xpath(xpath_expression)
        except etree.XPathEvalError as e:
            return HttpResponse(f"XPath evaluation error: {escape(str(e))}", status=400)


        # Format the results.  Escape the output to prevent XSS.
        formatted_results = [escape(str(result)) for result in results]
        output = ", ".join(formatted_results)

        return HttpResponse(output)

    except etree.XMLSyntaxError as e:
        return HttpResponse(f"XML parsing error: {escape(str(e))}", status=400)
    except Exception as e:
        # Log the error for debugging purposes.  Do *not* expose the full error message to the user.
        print(f"Unexpected error: {e}")  # Log the full error
        return HttpResponse("An unexpected error occurred.", status=500)


def is_valid_xpath(xpath_expression):
    """
    Validates the XPath expression against a strict allowlist.
    This is a placeholder and *must* be adapted to your specific needs.
    """
    # Example: Allow only simple attribute-based queries on a specific tag.
    # This is VERY restrictive.  Expand with extreme caution.
    allowed_pattern = r"^/tag\[@id='[a-zA-Z0-9]+'\]$"  # Example: /tag[@id='someId']
    import re
    return bool(re.match(allowed_pattern, xpath_expression))


def is_valid_xml(xml_data):
    """
    Validates the XML data against a strict allowlist.
    This is a placeholder and *must* be adapted to your specific needs.
    """
    # Example: Allow only a very simple XML structure.
    # This is VERY restrictive.  Expand with extreme caution.
    allowed_pattern = r"^<tag id='[a-zA-Z0-9]+'>.*?</tag>$"
    import re
    return bool(re.match(allowed_pattern, xml_data))

