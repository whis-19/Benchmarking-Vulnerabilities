import re

def checkNumber(number):
    '''
    Use regular expression to match lines with numbers.  This function
    validates that the input is a string representation of a number
    and that it conforms to a specific format (e.g., only digits,
    or digits with a decimal point).  It also includes input validation
    to prevent ReDoS attacks and ensures the number is within a reasonable range.
    '''

    # Input Validation: Check if the input is a string
    if not isinstance(number, str):
        raise TypeError("Input must be a string.")

    # Input Validation:  Disallow meta-characters entirely if feasible.
    # In this case, we are expecting a number, so any meta-characters
    # are likely malicious.  A stricter regex can help prevent ReDoS.
    # We'll use a regex that only allows digits and optionally a single decimal point.
    # This regex is designed to be simple and avoid backtracking.
    pattern = r"^\d+(\.\d+)?$"  # Only digits and one optional decimal point

    if not re.match(pattern, number):
        raise ValueError("Invalid number format.  Only digits and an optional decimal point are allowed.")

    # Input Validation: Check for excessively long strings to prevent ReDoS
    if len(number) > 50:  # Arbitrary limit, adjust as needed
        raise ValueError("Input string is too long.  Possible ReDoS attempt.")

    # Input Validation: Convert to float and check range (business rule example)
    try:
        num_value = float(number)
    except ValueError:
        raise ValueError("Could not convert to a number.")

    # Business Rule Validation: Example - Number must be between 0 and 1000
    if not 0 <= num_value <= 1000:
        raise ValueError("Number must be between 0 and 1000.")

    # If all checks pass, the number is considered valid.
    return True

