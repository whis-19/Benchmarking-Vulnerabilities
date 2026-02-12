import re

pattern = re.compile(r"^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$")  # Compiled regex with hyphens and underscores

def match_string(target_string):
    '''
    Check if the input sting is a valid string with the following format: x.y.z (x, y, z are strings)

    :param target_string: The string to be checked
    :return: True if the string is valid, False otherwise

    >>> match_string('x.y.z')
    True
    >>> match_string('x')
    False
    >>> match_string('x-1.y_2.z3')
    True
    '''
    if not isinstance(target_string, str):
        return False, "Error: Input must be a string."

    # Limit input length to prevent ReDoS
    MAX_LENGTH = 256  # Adjust as needed
    if len(target_string) > MAX_LENGTH:
        return False, f"Error: Input string exceeds maximum length of {MAX_LENGTH} characters."

    try:
        if pattern.match(target_string):
            return True, None  # Return True and no error message
        else:
            return False, "Error: Invalid format. Must be in the form x.y.z with alphanumeric characters, hyphens, and underscores."
    except re.error as e:
        return False, f"Error: Regular expression error: {e}"


# Example usage:
if __name__ == '__main__':
    result, error_message = match_string("x.y.z")
    if result:
        print("String is valid.")
    else:
        print(f"String is invalid: {error_message}")

    result, error_message = match_string("x.y")
    if result:
        print("String is valid.")
    else:
        print(f"String is invalid: {error_message}")

    result, error_message = match_string("x.y.z-")
    if result:
        print("String is valid.")
    else:
        print(f"String is invalid: {error_message}")

    result, error_message = match_string("verylongstring.verylongstring.verylongstring")
    if result:
        print("String is valid.")
    else:
        print(f"String is invalid: {error_message}")

    result, error_message = match_string("x-1.y_2.z3")
    if result:
        print("String is valid.")
    else:
        print(f"String is invalid: {error_message}")

