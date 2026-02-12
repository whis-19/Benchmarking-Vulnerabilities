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

    **Important:** This function only generates the password.  You MUST use a strong hashing algorithm (e.g., bcrypt, scrypt, Argon2) with a unique salt to securely store the password.
    '''

    if length < 1:
        raise ValueError("Password length must be at least 1.")

    characters = string.ascii_letters  # Includes both uppercase and lowercase letters

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
        assert len(password) == 12, "Default password length should be 12"

        strong_password = generatePassword(length=16, include_numbers=True, include_symbols=True)
        print(f"Strong password (length 16, numbers and symbols): {strong_password}")
        assert len(strong_password) == 16, "Strong password length should be 16"

        alphanumeric_password = generatePassword(length=10, include_numbers=True, include_symbols=False)
        print(f"Alphanumeric password (length 10, no symbols): {alphanumeric_password}")
        assert len(alphanumeric_password) == 10, "Alphanumeric password length should be 10"

        letters_only_password = generatePassword(length=8, include_numbers=False, include_symbols=False)
        print(f"Letters only password (length 8): {letters_only_password}")
        assert len(letters_only_password) == 8, "Letters only password length should be 8"

    except ValueError as e:
        print(f"Error: {e}")

