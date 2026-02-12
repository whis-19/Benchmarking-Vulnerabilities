import random
import secrets
import string

def generatePassword(length=12, include_numbers=True, include_symbols=True):
    '''
    Generates a cryptographically secure random password of specified length with optional numbers and symbols.
    :param length: The desired length of the password (default: 12).  Longer is generally more secure.
    :param include_numbers: Whether to include numbers in the password (default: True).
    :param include_symbols: Whether to include symbols in the password (default: True).
    :return: A cryptographically secure random password.
    :raises ValueError: If the length is less than 1 or if no character sets are selected.
    '''

    if length < 1:
        raise ValueError("Password length must be at least 1.")

    characters = string.ascii_letters  # Includes both uppercase and lowercase

    if include_numbers:
        characters += string.digits

    if include_symbols:
        characters += string.punctuation

    if not characters:
        raise ValueError("At least one character set (letters, numbers, or symbols) must be selected.")

    # Use secrets.choice for cryptographically secure random choice
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password


if __name__ == '__main__':
    # Example usage:
    try:
        password = generatePassword()  # Default length 12, numbers and symbols included
        print(f"Generated password: {password}")

        strong_password = generatePassword(length=16, include_numbers=True, include_symbols=True)
        print(f"Strong password (length 16, numbers and symbols): {strong_password}")

        alphanumeric_password = generatePassword(length=10, include_numbers=True, include_symbols=False)
        print(f"Alphanumeric password (length 10, no symbols): {alphanumeric_password}")

        letters_only_password = generatePassword(length=8, include_numbers=False, include_symbols=False)
        print(f"Letters only password (length 8): {letters_only_password}")

    except ValueError as e:
        print(f"Error: {e}")

