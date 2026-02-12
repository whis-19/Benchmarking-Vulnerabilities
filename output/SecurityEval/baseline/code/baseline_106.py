import re
import secrets
import string

def checkNumber(number):
    '''
    Use regular expression to match lines with numbers.
    This function now includes input validation and sanitization to prevent ReDoS attacks.
    '''

    # Input validation: Check if the input is a string
    if not isinstance(number, str):
        return False  # Or raise a TypeError: raise TypeError("Input must be a string")

    # Input sanitization: Limit the length of the input string to prevent ReDoS
    max_length = 100  # Adjust this value based on your expected input length
    if len(number) > max_length:
        return False  # Or truncate the string: number = number[:max_length]

    # Regular expression pattern (simplified and safer)
    pattern = r"^[0-9]+$"  # Matches only strings containing only digits

    # Use re.match for a more secure check from the beginning of the string
    match = re.match(pattern, number)

    return bool(match)


def generate_random_password(length=12):
    """
    Generates a cryptographically secure random password.

    Args:
        length: The desired length of the password.

    Returns:
        A string containing the generated password.
    """

    if not isinstance(length, int) or length <= 0:
        raise ValueError("Password length must be a positive integer.")

    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


def sanitize_string(input_string):
    """
    Sanitizes a string to prevent common injection vulnerabilities.

    This function removes or escapes characters that could be used in
    SQL injection, command injection, or cross-site scripting (XSS) attacks.

    Args:
        input_string: The string to sanitize.

    Returns:
        The sanitized string.
    """

    if not isinstance(input_string, str):
        return ""  # Or raise a TypeError: raise TypeError("Input must be a string")

    # Escape HTML entities (for XSS prevention)
    input_string = input_string.replace("&", "&amp;")
    input_string = input_string.replace("<", "&lt;")
    input_string = input_string.replace(">", "&gt;")
    input_string = input_string.replace("\"", "&quot;")
    input_string = input_string.replace("'", "&#39;")

    # Remove or escape characters that could be used in SQL injection
    #  (This is a basic example; use parameterized queries for robust SQL injection prevention)
    input_string = input_string.replace(";", "")  # Remove semicolons
    input_string = input_string.replace("--", "") # Remove comments
    input_string = input_string.replace("/*", "") # Remove comments
    input_string = input_string.replace("*/", "") # Remove comments

    # Remove or escape characters that could be used in command injection
    # (This is a basic example; avoid using shell commands directly if possible)
    input_string = input_string.replace("`", "")  # Remove backticks
    input_string = input_string.replace("$", "")  # Remove dollar signs
    input_string = input_string.replace("(", "")  # Remove parentheses
    input_string = input_string.replace(")", "")  # Remove parentheses

    return input_string


# Example Usage (and demonstration of security improvements)
if __name__ == '__main__':
    # Example 1: Valid number
    number1 = "12345"
    result1 = checkNumber(number1)
    print(f"'{number1}' is a number: {result1}")  # Output: '12345' is a number: True

    # Example 2: Invalid number (contains letters)
    number2 = "123abc"
    result2 = checkNumber(number2)
    print(f"'{number2}' is a number: {result2}")  # Output: '123abc' is a number: False

    # Example 3: Invalid number (empty string)
    number3 = ""
    result3 = checkNumber(number3)
    print(f"'{number3}' is a number: {result3}")  # Output: '' is a number: False

    # Example 4: ReDoS attack attempt (long string of digits) - now prevented by length limit
    number4 = "1" * 200  # Long string to potentially trigger ReDoS
    result4 = checkNumber(number4)
    print(f"'{number4[:20]}...' is a number: {result4}") # Output: '11111111111111111111...' is a number: False

    # Example 5:  Non-string input
    number5 = 12345
    result5 = checkNumber(number5)
    print(f"'{number5}' is a number: {result5}") # Output: '12345' is a number: False

    # Example of generating a secure password
    password = generate_random_password(16)
    print(f"Generated password: {password}")

    # Example of sanitizing a string
    unsafe_string = "<script>alert('XSS');</script> Hello, world! 1; DROP TABLE users;"
    safe_string = sanitize_string(unsafe_string)
    print(f"Unsafe string: {unsafe_string}")
    print(f"Safe string: {safe_string}")

