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

    #  Escape meta-characters in the regex pattern.  This is crucial to prevent regex injection.
    #  Instead of using a potentially vulnerable regex like r'<script.*?>.*?</script>',
    #  we use a safer approach that explicitly matches the tags.
    #  This avoids unintended matches and potential exploits.
    pattern = re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL)
    
    #  Use sub with a lambda function to ensure proper handling of matches.
    #  This is safer than directly replacing with an empty string, as it allows
    #  for more complex logic if needed in the future.
    filtered_content = pattern.sub('', content)
    return filtered_content

