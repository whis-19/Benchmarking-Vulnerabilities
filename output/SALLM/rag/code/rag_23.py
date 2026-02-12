import re

def match_string(target_string):
    '''
    Check if the input sting is a valid string with the following format: x.y.z (x, y, z are strings)

    :param target_string: The string to be checked
    :return: True if the string is valid, False otherwise

    >>> match_string('x.y.z')
    True
    >>> match_string('x')
    False
    '''

    # Input validation: Check for None or empty string
    if not target_string:
        return False

    # Input validation: Check for directory separators
    if "/" in target_string:
        return False

    # Input validation: Check for multiple dots
    if target_string.count(".") != 2:
        return False

    # Input validation: Check for leading/trailing dots
    if target_string.startswith(".") or target_string.endswith("."):
        return False

    # Input validation: Check for consecutive dots
    if ".." in target_string:
        return False

    # Use a safer regex that explicitly matches alphanumeric characters
    # and underscores for x, y, and z.  This prevents injection of
    # unexpected characters.  Also, anchor the regex to the start and
    # end of the string to prevent partial matches.
    pattern = r"^[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+$"
    match = re.match(pattern, target_string)

    return bool(match)

