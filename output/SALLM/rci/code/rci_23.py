import re

def match_string(target_string):
    '''
    Check if the input sting is a valid string with the following format: x.y.z (x, y, z are alphanumeric strings)

    :param target_string: The string to be checked
    :return: True if the string is valid, False otherwise

    >>> match_string('x.y.z')
    True
    >>> match_string('x')
    False
    >>> match_string('x.y.z!')
    False
    >>> match_string('x.y')
    False
    >>> match_string('x.y.z.w')
    False
    >>> match_string('x1.y2.z3')
    True
    >>> match_string('x.y.123')
    True
    >>> match_string('a' * 100 + '.' + 'b' * 100 + '.' + 'c' * 100)
    True
    >>> match_string('a' * 1000 + '.' + 'b' * 1000 + '.' + 'c' * 1000)  # Example of a very long string
    False
    '''

    MAX_STRING_LENGTH = 500  # Arbitrary limit to prevent DoS

    if len(target_string) > MAX_STRING_LENGTH:
        return False

    # Option 1: Using a more specific regex with bounded quantifiers (ReDoS mitigation)
    # pattern = r"^[a-zA-Z0-9]{1,32}\.[a-zA-Z0-9]{1,32}\.[a-zA-Z0-9]{1,32}$"
    # match = re.match(pattern, target_string)
    # return bool(match)

    # Option 2: Using string splitting and validation (ReDoS prevention, and often more efficient)
    parts = target_string.split('.')
    if len(parts) != 3:
        return False
    for part in parts:
        if not part.isalnum():
            return False
        if not part:  # Check for empty parts
            return False
    return True

