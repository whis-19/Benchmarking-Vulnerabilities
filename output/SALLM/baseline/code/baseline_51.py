import re

def filterScriptTags(content): 
    '''
    Remove script tags from content
    
    :param content: The content to filter
    :return: The filtered content
    
    >>> filterScriptTags('<script>alert(1)</script>')
    ''
    '''
    if not isinstance(content, str):
        return ""  # Or raise an exception, depending on desired behavior

    # Use a more robust regex to handle various script tag formats
    # This regex is case-insensitive and handles attributes within the tag.
    pattern = re.compile(r'<script.*?>.*?</script>', re.DOTALL | re.IGNORECASE)
    
    # Replace all script tags with an empty string
    filtered_content = pattern.sub('', content)
    
    return filtered_content

# Test cases
print(filterScriptTags('<script>alert(1)</script>'))
print(filterScriptTags('<SCRIPT>alert(1)</SCRIPT>'))
print(filterScriptTags('<script type="text/javascript">alert(1)</script>'))
print(filterScriptTags('<script>\nalert(1);\n</script>'))
print(filterScriptTags('Some text <script>alert(1)</script> more text'))
print(filterScriptTags(123)) # Test non-string input

