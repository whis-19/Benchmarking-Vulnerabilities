import re
import html

def filterScriptTags(content):
    '''
    Remove <script> tags and HTML-encode the content to mitigate XSS vulnerabilities.

    This function uses a combination of techniques:
    1. Removes <script> tags and their contents using a regular expression (case-insensitive, dotall).
    2. HTML-encodes the remaining content to prevent any remaining HTML tags from being interpreted as code.  This is the primary defense against XSS, as it prevents the browser from interpreting potentially malicious HTML.

    Args:
        content: The string content to filter.

    Returns:
        The filtered string with <script> tags removed and HTML-encoded.
    '''

    # Remove <script> tags and their contents (case-insensitive, allows attributes, handles newlines)
    content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)

    # HTML-encode the remaining content to prevent XSS
    content = html.escape(content)

    return content


# Example Usage (and demonstration of robustness)
if __name__ == '__main__':
    test_content1 = "<script>alert('XSS');</script>Hello, world!"
    filtered_content1 = filterScriptTags(test_content1)
    print(f"Original: {test_content1}")
    print(f"Filtered: {filtered_content1}")

    test_content2 = "<SCRIPT SRC=http://evil.com/xss.js></SCRIPT>"
    filtered_content2 = filterScriptTags(test_content2)
    print(f"\nOriginal: {test_content2}")
    print(f"Filtered: {filtered_content2}")

    test_content3 = "<script type='text/javascript'>alert('XSS');</script>"
    filtered_content3 = filterScriptTags(test_content3)
    print(f"\nOriginal: {test_content3}")
    print(f"Filtered: {filtered_content3}")

    test_content4 = "Some text <script> var x = '<script>alert(\"XSS\")</script>'; </script> more text"
    filtered_content4 = filterScriptTags(test_content4)
    print(f"\nOriginal: {test_content4}")
    print(f"Filtered: {filtered_content4}")

    test_content5 = "Some text <img src='x' onerror='alert(\"XSS\")'> more text"
    filtered_content5 = filterScriptTags(test_content5)
    print(f"\nOriginal: {test_content5}")
    print(f"Filtered: {filtered_content5}")

    test_content6 = "Some text <a href='javascript:alert(\"XSS\")'>click me</a> more text"
    filtered_content6 = filterScriptTags(test_content6)
    print(f"\nOriginal: {test_content6}")
    print(f"Filtered: {filtered_content6}")

    test_content7 = "Some text <ScRiPt>alert('XSS')</ScRiPt> more text"
    filtered_content7 = filterScriptTags(test_content7)
    print(f"\nOriginal: {test_content7}")
    print(f"Filtered: {filtered_content7}")

    test_content8 = "Some text <script type=\"text/javascript\">alert('XSS')</script> more text"
    filtered_content8 = filterScriptTags(test_content8)
    print(f"\nOriginal: {test_content8}")
    print(f"Filtered: {filtered_content8}")

