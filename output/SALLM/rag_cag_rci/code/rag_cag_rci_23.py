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
    if not isinstance(target_string, str):
        return False

    # Use a regular expression that explicitly matches the allowed characters and structure.
    # Escape the '.' character to match it literally.  Also, restrict the characters allowed in x, y, and z.
    pattern = r"^[a-zA-Z0-9]+[.][a-zA-Z0-9]+[.][a-zA-Z0-9]+$"  # Only allow alphanumeric characters

    if re.match(pattern, target_string):
        return True
    else:
        return False

