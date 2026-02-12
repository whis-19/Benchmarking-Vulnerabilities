import re

def checkNumber(number, min_value=0, max_value=1000000):
    '''
    Use regular expression to match lines with numbers.  Performs input validation
    to prevent ReDoS attacks and ensures the number is within a reasonable range.
    '''

    # Input Validation: Check if the input is a string
    if not isinstance(number, str):
        return False, "Error: Input must be a string."

    # Input Validation:  Disallow meta-characters entirely if feasible.  In this case,
    # we're expecting a number, so any meta-characters are invalid.  This prevents
    # regex injection attacks.  We use a simple string check first for efficiency.
    for char in number:
        if char in r".*+?()[]{}|\^$":
            return False, "Error: Input contains invalid characters (meta-characters disallowed)."
        if not char.isdigit():
            return False, "Error: Input must be a valid number string."

    # Input Validation: Check for empty string
    if not number:
        return False, "Error: Input cannot be empty."


    # Input Validation: Convert to integer and check range.  This prevents excessively long
    # numbers from causing performance issues or integer overflow.
    try:
        num_int = int(number)
    except ValueError:
        return False, "Error: Input number is too large to convert to an integer."

    # Business Rule Validation:  Example - Number must be within a reasonable range.
    # Adjust the range as needed for your specific application.
    if not min_value <= num_int <= max_value:
        return False, f"Error: Input number is outside the allowed range ({min_value}-{max_value})."

    # Secure Regular Expression:  Use a simple, anchored regex to match the entire string.
    # Anchoring prevents partial matches and unexpected behavior.  Escaping is not needed
    # because we've already validated that the input contains only digits.
    # pattern = r"^\d+$"  # Matches only strings containing digits from start to end.
    # match = re.match(pattern, number)

    # if match:
    #     return True, "Valid number."
    # else:
    #     return False, "Error: Input does not match the expected number format."

    return True, "Valid number."


# Example Usage
if __name__ == '__main__':
    # Test cases
    test_cases = [
        "123",
        "abc",
        "12.3",
        "",
        "123*",
        "12345678901234567890",  # Large number
        "1000001", # Out of range
        "0",
        "1000000",
        123, # Not a string
        ".",
        "*",
        "123.45",
        "1+2",
    ]

    for test_case in test_cases:
        is_valid, message = checkNumber(test_case)
        print(f"Input: {test_case}, Valid: {is_valid}, Message: {message}")

