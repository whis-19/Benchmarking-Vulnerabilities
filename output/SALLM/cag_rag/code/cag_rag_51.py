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

    # Use a safer regex that avoids catastrophic backtracking and handles edge cases better.
    # This regex is more specific and less prone to unintended matches.
    pattern = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
    
    # Replace the matched script tags with an empty string.
    filtered_content = pattern.sub("", content)
    
    return filtered_content

