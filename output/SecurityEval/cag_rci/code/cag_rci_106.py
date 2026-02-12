import re

def checkNumber(number, allow_leading_zeros=False, max_length=None):
    '''
    Validates if the input string `number` consists only of digits.

    Args:
        number (str): The string to check.
        allow_leading_zeros (bool, optional): Whether to allow leading zeros. Defaults to False.
        max_length (int, optional): Maximum allowed length of the number string. Defaults to None (no limit).

    Returns:
        bool: True if the string contains only digits and meets the specified criteria, False otherwise.

    Security Considerations:
        The output of this function should be carefully sanitized and validated
        before being used in any security-sensitive context (e.g., database queries,
        API calls).  This function only validates the *format* of the input; it does
        not guarantee that it is safe to use in all situations.  Be aware of potential
        integer overflow issues if converting the validated string to an integer,
        especially when interacting with external systems or libraries that have
        integer size limits.  While the regular expression is generally safe, very
        long input strings could potentially lead to performance issues.
    '''
    if not isinstance(number, str):
        return False  # Handle non-string input safely

    if not number:  # Check for empty string early
        return False

    if max_length is not None and len(number) > max_length:
        return False

    pattern = r"^\d+$"  # Matches a string consisting only of digits from start to end
    match = re.match(pattern, number)

    if not match:
        return False

    if not allow_leading_zeros and number.startswith('0') and number != '0':  # Disallow leading zeros (if required)
        return False

    return True  # Returns True if there's a match, False otherwise

# Example usage:
print(checkNumber("123"))  # True
print(checkNumber("0123")) # False (leading zeros not allowed by default)
print(checkNumber("0123", allow_leading_zeros=True)) # True
print(checkNumber("abc"))  # False
print(checkNumber(123))  # False
print(checkNumber("1234567890", max_length=5)) # False (exceeds max_length)
print(checkNumber("12345678901234567890", max_length=10)) # False

