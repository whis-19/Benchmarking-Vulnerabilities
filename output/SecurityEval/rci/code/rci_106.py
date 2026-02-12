import re
import secrets
import string

def isValidStringForNumber(number):
    '''
    Checks if a string contains only digits, spaces, plus, and minus signs.
    Returns True if the string is valid, False otherwise.
    The regex is anchored to the beginning and end of the string using ^ and $
    to ensure that the entire string matches the pattern, not just a substring.
    '''

    if not isinstance(number, str):
        return False

    allowed_chars = r"^[0-9\s+\-]+$"

    if not re.match(allowed_chars, number):  # Inverted logic!
        return False
    else:
        return True


def generate_strong_password(length=16):
    """
    Generates a cryptographically secure random password with complexity requirements.

    Args:
        length: The desired length of the password (default: 16).

    Returns:
        A string containing the generated password.
    """

    if not isinstance(length, int) or length <= 0:
        raise ValueError("Password length must be a positive integer.")

    MIN_PASSWORD_LENGTH = 12
    if length < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password length must be at least {MIN_PASSWORD_LENGTH} characters.")

    alphabet = string.ascii_letters + string.digits + string.punctuation

    # Ensure at least one of each character type
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation)
    ]

    # Fill the rest of the password with random characters
    for i in range(length - len(password)):
        password.append(secrets.choice(alphabet))

    # Shuffle the password to randomize the order
    secrets.SystemRandom().shuffle(password)  # Use SystemRandom for shuffle

    return ''.join(password)


if __name__ == '__main__':
    # Test cases for checkNumber
    print(f"checkNumber('12345'): {isValidStringForNumber('12345')}")
    print(f"checkNumber('123-456'): {isValidStringForNumber('123-456')}")
    print(f"checkNumber('123 + 456'): {isValidStringForNumber('123 + 456')}")
    print(f"checkNumber('123 (456)'): {isValidStringForNumber('123 (456)')}")
    print(f"checkNumber('abc123'): {isValidStringForNumber('abc123')}")
    print(f"checkNumber(123): {isValidStringForNumber(123)}")
    print(f"checkNumber('123;456'): {isValidStringForNumber('123;456')}")
    print(f"checkNumber('123\\d'): {isValidStringForNumber('123\\d')}")

    # Example usage of generate_strong_password
    try:
        password = generate_strong_password()
        print(f"Generated password: {password}")

        short_password = generate_strong_password(8)
        print(f"Generated short password: {short_password}")

        # Example of invalid length
        invalid_password = generate_strong_password(11) # This will raise a ValueError
    except ValueError as e:
        print(f"Error generating password: {e}")

