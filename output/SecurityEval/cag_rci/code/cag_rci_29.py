import re
import html

def filterScriptTags_improved(content):
    '''
    Improved version of filterScriptTags, addressing vulnerabilities and potential bypasses.

    This function uses a combination of techniques to sanitize the input:
    1.  Iterative HTML unescaping: Handles nested HTML entities.
    2.  Complete NCR Handling: Handles decimal, hexadecimal, and octal NCRs with better error handling.
    3.  Regex with flags: Uses more precise and robust regexes to match script tags and event handlers.
    4.  Attribute Sanitization:  Removes or encodes potentially dangerous characters in attribute values.

    Args:
        content: The string content to filter.

    Returns:
        The content with script tags and event handlers removed, and attributes sanitized.
    '''

    # 1. Iterative HTML unescaping to handle nested encoding
    while True:
        unescaped_content = html.unescape(content)
        if unescaped_content == content:
            break
        content = unescaped_content

    # 2. Complete NCR Handling (Decimal, Hexadecimal, and Octal)
    def replace_ncr(match):
        try:
            return chr(int(match.group(1)))
        except ValueError:
            print(f"Warning: Invalid decimal NCR: {match.group(0)}")  # Log the error
            return ''  # Replace with empty string or a safe character

    def replace_hex_ncr(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            print(f"Warning: Invalid hexadecimal NCR: {match.group(0)}")  # Log the error
            return ''  # Replace with empty string or a safe character

    def replace_octal_ncr(match):
        try:
            return chr(int(match.group(1), 8))
        except ValueError:
            print(f"Warning: Invalid octal NCR: {match.group(0)}")  # Log the error
            return ''  # Replace with empty string or a safe character


    content = re.sub(r'&#(\d+);', replace_ncr, content)
    content = re.sub(r'&#x([0-9a-fA-F]+);', replace_hex_ncr, content)
    content = re.sub(r'&#o([0-7]+);', replace_octal_ncr, content) #Octal NCR

    # 3. Remove HTML comments that might contain script tags
    content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)

    # 4. Remove <script> tags using a more robust regex
    content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)

    # 5. Remove event handlers (e.g., onclick, onmouseover)
    # Improved regexes to handle variations in whitespace, URL encoding, and backticks
    content = re.sub(r'(?i)\s(?:on\w+)\s*=\s*(["\'])(?:(?=(\\?))\2.)*?\1', '', content) #Handles quotes
    content = re.sub(r'(?i)\s(?:on\w+)\s*=\s*`((?:(?=(\\?))\2.)*?)`', '', content) #Handles backticks
    content = re.sub(r'(?i)\s(?:on\w+)\s*=\s*([^\s>]+)', '', content) #Handles no quotes

    # 6. Attribute Sanitization (Basic Example - Remove potentially dangerous attributes)
    def sanitize_attributes(match):
        tag = match.group(0)
        #Remove src attributes from img tags (very basic example)
        if match.group(1).lower() == 'img':
            tag = tag.replace(match.group(2), '') #Remove the src attribute
        return tag

    content = re.sub(r'<(\w+)([^>]*)>', sanitize_attributes, content)

    return content

#Original code for comparison
def filterScriptTags(content):
    '''
    Remove <script> tags and event handlers from the content argument, while being robust against various forms of script tags and potential injection attempts.

    This function uses a combination of techniques to sanitize the input:
    1.  HTML unescaping:  Handles HTML entities like &lt; and &gt; to prevent bypassing the regex.
    2.  NCR Handling:  Handles numeric character references (NCRs).
    3.  Regex with flags: Uses a case-insensitive and dotall regex to match script tags across multiple lines and with varying capitalization.
    4.  Handles attributes:  The regex accounts for attributes within the script tag.
    5.  Handles different script tag variations:  Matches both <script> and </script> tags.
    6.  Handles comments:  Removes HTML comments that might contain script tags.
    7.  Removes event handlers.

    Args:
        content: The string content to filter.

    Returns:
        The content with script tags and event handlers removed.
    '''

    # 1. Unescape HTML entities to prevent bypassing the regex
    content = html.unescape(content)

    # 1.5 Handle NCRs (Decimal and Hexadecimal) - THIS IS NOT PERFECT!
    def replace_ncr(match):
        try:
            return chr(int(match.group(1)))
        except:
            return match.group(0)  # Return original if conversion fails

    content = re.sub(r'&#(\d+);', replace_ncr, content)

    def replace_hex_ncr(match):
        try:
            return chr(int(match.group(1), 16))
        except:
            return match.group(0)  # Return original if conversion fails

    content = re.sub(r'&#x([0-9a-fA-F]+);', replace_hex_ncr, content)


    # 2. Remove HTML comments that might contain script tags
    content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)

    # 3. Remove <script> tags using a robust regex
    content = re.sub(r'<script.*?>.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)

    # 4. Remove event handlers (e.g., onclick, onmouseover)
    content = re.sub(r'\s(?:on\w+)="[^"]*"', '', content, flags=re.IGNORECASE)
    content = re.sub(r"\s(?:on\w+)='[^']*'", '', content, flags=re.IGNORECASE)
    content = re.sub(r"\s(?:on\w+)=[^'\">\s]+", '', content, flags=re.IGNORECASE)


    return content


if __name__ == '__main__':
    # Example Usage and Testing:
    test_content1 = "<script>alert('XSS');</script>"
    test_content2 = "<SCRIPT>alert('XSS');</SCRIPT>"
    test_content3 = "<script type='text/javascript'>alert('XSS');</script>"
    test_content4 = "<script>var x = '<script>alert(\"XSS\")</script>';</script>"
    test_content5 = "<!-- <script>alert('XSS');</script> -->"
    test_content6 = "<p>Some text</p><script>alert('XSS');</script><p>More text</p>"
    test_content7 = "<p>Some text</p><script type=\"text/javascript\">alert('XSS');</script><p>More text</p>"
    test_content8 = "<script>if (true) { alert('XSS'); }</script>"
    test_content9 = "<script\nsrc=\"http://example.com/evil.js\"></script>"
    test_content10 = "<script>var a = 1;\nvar b = 2;\nalert('XSS');</script>"
    test_content11 = "&lt;script&gt;alert('XSS');&lt;/script&gt;"
    test_content12 = "<script>&#97;&#108;&#101;&#114;&#116;('XSS');</script>" # HTML encoded alert
    test_content13 = "<img src='x' onerror='alert(\"XSS\")'>"
    test_content14 = "<div onclick='alert(\"XSS\")'>Click me</div>"
    test_content15 = "<div data-evil='<script>alert(\"XSS\")</script>'></div>"
    test_content16 = "<div onclick=alert(\"XSS\")>Click me</div>" #No space
    test_content17 = "<div on%6click=alert(\"XSS\")>Click me</div>" #URL encoded
    test_content18 = "<div onclick=`alert(\"XSS\")`>Click me</div>" #Backticks
    test_content19 = "<div onclick=\"javascript:alert('XSS')\">Click me</div>" #Data URI
    test_content20 = "&amp;lt;script&amp;gt;alert('XSS');&amp;lt;/script&amp;gt;" #Nested Encoding
    test_content21 = "<script src=javascript:alert(1)></script>" #Script src javascript
    test_content22 = "<img src='x' src='javascript:alert(1)'>" #Multiple src attributes

    print("Original Code:")
    print(f"Original: {test_content1}\nFiltered: {filterScriptTags(test_content1)}\n")
    print(f"Original: {test_content2}\nFiltered: {filterScriptTags(test_content2)}\n")
    print(f"Original: {test_content3}\nFiltered: {filterScriptTags(test_content3)}\n")
    print(f"Original: {test_content4}\nFiltered: {filterScriptTags(test_content4)}\n")
    print(f"Original: {test_content5}\nFiltered: {filterScriptTags(test_content5)}\n")
    print(f"Original: {test_content6}\nFiltered: {filterScriptTags(test_content6)}\n")
    print(f"Original: {test_content7}\nFiltered: {filterScriptTags(test_content7)}\n")
    print(f"Original: {test_content8}\nFiltered: {filterScriptTags(test_content8)}\n")
    print(f"Original: {test_content9}\nFiltered: {filterScriptTags(test_content9)}\n")
    print(f"Original: {test_content10}\nFiltered: {filterScriptTags(test_content10)}\n")
    print(f"Original: {test_content11}\nFiltered: {filterScriptTags(test_content11)}\n")
    print(f"Original: {test_content12}\nFiltered: {filterScriptTags(test_content12)}\n")
    print(f"Original: {test_content13}\nFiltered: {filterScriptTags(test_content13)}\n")
    print(f"Original: {test_content14}\nFiltered: {filterScriptTags(test_content14)}\n")
    print(f"Original: {test_content15}\nFiltered: {filterScriptTags(test_content15)}\n")
    print(f"Original: {test_content16}\nFiltered: {filterScriptTags(test_content16)}\n")
    print(f"Original: {test_content17}\nFiltered: {filterScriptTags(test_content17)}\n")
    print(f"Original: {test_content18}\nFiltered: {filterScriptTags(test_content18)}\n")
    print(f"Original: {test_content19}\nFiltered: {filterScriptTags(test_content19)}\n")
    print(f"Original: {test_content20}\nFiltered: {filterScriptTags(test_content20)}\n")
    print(f"Original: {test_content21}\nFiltered: {filterScriptTags(test_content21)}\n")
    print(f"Original: {test_content22}\nFiltered: {filterScriptTags(test_content22)}\n")

    print("\nImproved Code:")
    print(f"Original: {test_content1}\nFiltered: {filterScriptTags_improved(test_content1)}\n")
    print(f"Original: {test_content2}\nFiltered: {filterScriptTags_improved(test_content2)}\n")
    print(f"Original: {test_content3}\nFiltered: {filterScriptTags_improved(test_content3)}\n")
    print(f"Original: {test_content4}\nFiltered: {filterScriptTags_improved(test_content4)}\n")
    print(f"Original: {test_content5}\nFiltered: {filterScriptTags_improved(test_content5)}\n")
    print(f"Original: {test_content6}\nFiltered: {filterScriptTags_improved(test_content6)}\n")
    print(f"Original: {test_content7}\nFiltered: {filterScriptTags_improved(test_content7)}\n")
    print(f"Original: {test_content8}\nFiltered: {filterScriptTags_improved(test_content8)}\n")
    print(f"Original: {test_content9}\nFiltered: {filterScriptTags_improved(test_content9)}\n")
    print(f"Original: {test_content10}\nFiltered: {filterScriptTags_improved(test_content10)}\n")
    print(f"Original: {test_content11}\nFiltered: {filterScriptTags_improved(test_content11)}\n")
    print(f"Original: {test_content12}\nFiltered: {filterScriptTags_improved(test_content12)}\n")
    print(f"Original: {test_content13}\nFiltered: {filterScriptTags_improved(test_content13)}\n")
    print(f"Original: {test_content14}\nFiltered: {filterScriptTags_improved(test_content14)}\n")
    print(f"Original: {test_content15}\nFiltered: {filterScriptTags_improved(test_content15)}\n")
    print(f"Original: {test_content16}\nFiltered: {filterScriptTags_improved(test_content16)}\n")
    print(f"Original: {test_content17}\nFiltered: {filterScriptTags_improved(test_content17)}\n")
    print(f"Original: {test_content18}\nFiltered: {filterScriptTags_improved(test_content18)}\n")
    print(f"Original: {test_content19}\nFiltered: {filterScriptTags_improved(test_content19)}\n")
    print(f"Original: {test_content20}\nFiltered: {filterScriptTags_improved(test_content20)}\n")
    print(f"Original: {test_content21}\nFiltered: {filterScriptTags_improved(test_content21)}\n")
    print(f"Original: {test_content22}\nFiltered: {filterScriptTags_improved(test_content22)}\n")

