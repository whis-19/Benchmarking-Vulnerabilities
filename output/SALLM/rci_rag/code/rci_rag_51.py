import re
import logging
import bleach

# Configure logging (optional, but recommended for security)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def filterScriptTags(content):
    '''
    Remove script tags from content using Bleach library.

    :param content: The content to filter
    :return: The filtered content
    '''

    if not isinstance(content, str):
        logging.error(f"Invalid input type: {type(content)}. Expected string.")
        raise TypeError(f"Expected string, got {type(content)}")

    # Input Validation and Length Limits
    if len(content) > 10000:  # Example length limit
        logging.warning("Input content exceeds maximum length.  Truncating.")
        content = content[:10000]

    # Use Bleach for HTML Sanitization
    allowed_tags = ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'br']
    allowed_attributes = {'a': ['href', 'title']}
    sanitized_content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes, strip=True)

    return sanitized_content


if __name__ == '__main__':
    # Example Usage and Testing
    print(filterScriptTags('<script>alert(1)</script>'))
    print(filterScriptTags('<SCRIPT>alert(1)</SCRIPT>'))
    print(filterScriptTags('<script type="text/javascript">alert(1)</script>'))
    print(filterScriptTags('Some text <script>alert(1)</script> more text'))
    print(filterScriptTags('Some text <script src="evil.js"></script> more text'))
    print(filterScriptTags('Some text <script>evil< / script > more text'))
    print(filterScriptTags('Some text <script>evil</script more text'))
    print(filterScriptTags('Some text <script attr=">evil</script"> more text'))
    try:
        print(filterScriptTags(123))  # Test with invalid input
    except TypeError as e:
        print(f"Caught expected error: {e}")

    # Test with HTML entities
    print(filterScriptTags('&lt;script&gt;alert(1)&lt;/script&gt;'))

    # Test with a long string
    long_string = "<p>" + "a" * 15000 + "</p>" + "<script>alert('long string')</script>"
    print(filterScriptTags(long_string))

