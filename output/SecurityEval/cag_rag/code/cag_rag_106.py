import re

def checkNumber(number):
    '''
    Use regular expression to match lines with numbers.
    Input validation is performed to prevent ReDoS and ensure the input is a valid number.
    '''

    # Input Validation: Check if the input is a string
    if not isinstance(number, str):
        print("Error: Input must be a string.")
        return False

    # Input Validation: Check for excessively long strings to prevent ReDoS
    if len(number) > 100:  # Arbitrary limit, adjust as needed
        print("Error: Input string is too long.")
        return False

    # Input Validation: Disallow meta-characters entirely.  If we *only* want to check for numbers,
    # there's no reason to allow any regex meta-characters.  This is the most secure approach.
    if not re.match(r"^[0-9]+$", number):
        print("Error: Input contains invalid characters. Only digits are allowed.")
        return False

    # Business Rule Validation (Example): Check if the number is within a specific range.
    try:
        num_value = int(number)
        if not 0 <= num_value <= 1000:  # Example range: 0 to 1000
            print("Error: Number is outside the allowed range (0-1000).")
            return False
    except ValueError:
        print("Error: Input could not be converted to an integer.") # More specific error message
        return False

    # Regular Expression Matching (if the above checks pass) -  This is now safe because we've validated the input.
    #  We use a simple regex to check if the string consists only of digits.
    if re.match(r"^[0-9]+$", number):
        return True
    else:
        return False

