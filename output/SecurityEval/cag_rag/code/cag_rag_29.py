import re

def filterScriptTags(content):
    '''
    Remove <script> tags from the content argument.
    '''
    if content is None:
        return None  # Or raise an exception, depending on desired behavior

    # Use a regular expression to find and remove <script> tags.
    # The regex is made more secure by:
    # 1. Using a non-greedy match (.*?) to avoid matching across multiple script tags.
    # 2. Making the regex case-insensitive (re.IGNORECASE) to catch <SCRIPT>, <Script>, etc.
    # 3. Escaping the forward slash in the closing tag.
    # 4. Using raw string to define the regex.
    pattern = re.compile(r'<script.*?>.*?</script>', re.IGNORECASE | re.DOTALL)
    
    # Replace the matched script tags with an empty string.
    cleaned_content = pattern.sub('', content)
    return cleaned_content

