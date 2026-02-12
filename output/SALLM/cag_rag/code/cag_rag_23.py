import re
import html

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

    # Sanitize the input string to prevent HTML injection
    target_string = html.escape(target_string)

    # Use a regex that explicitly matches literal dots.  Disallow other metacharacters.
    pattern = r'^[a-zA-Z0-9]+[.][a-zA-Z0-9]+[.][a-zA-Z0-9]+$'

    if re.match(pattern, target_string):
        return True
    else:
        return False

