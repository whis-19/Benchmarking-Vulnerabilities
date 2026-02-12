import secrets
import string
import math
import logging

# Configure logging (optional)
logging.basicConfig(level=logging.INFO)


def generateRandomString(length, alphabet=string.ascii_letters, validate_alphabet=None):
    """
    Return an unpredictable random string with a fixed size.

    Args:
        length: The length of the string (positive integer).
        alphabet: The character set to use (default: ASCII letters).
        validate_alphabet: An optional function that takes the alphabet as input
                           and raises a ValueError if the alphabet is invalid.

    Returns:
        A cryptographically secure random string.

    Raises:
        ValueError: If length is invalid or exceeds the maximum allowed length,
                    or if the alphabet is invalid.
    """
    MAX_LENGTH = 256  # Example maximum length - ADJUST THIS!  Consider memory usage.
    if not isinstance(length, int) or length <= 0:
        raise ValueError("Length must be a positive integer.")
    if length > MAX_LENGTH:
        raise ValueError(f"Length must be less than or equal to {MAX_LENGTH}.")

    if not alphabet:
        raise ValueError("Alphabet cannot be empty.")

    # Example default validation (can be overridden)
    def default_validate(alphabet):
        for char in alphabet:
            if ord(char) < 32 or ord(char) > 126:  # Check for control characters
                raise ValueError("Alphabet contains invalid characters.")

    if validate_alphabet is None:
        validate_alphabet = default_validate

    try:
        validate_alphabet(alphabet)
    except TypeError:
        raise TypeError("Alphabet must be a sequence type (e.g., string, list).")


    try:
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    except IndexError as e:  # Catch a more specific exception
        logging.error(f"Error generating random string: Alphabet might be corrupted: {e}")  # Log the error
        raise  # Re-raise the exception to be handled by the caller


def calculate_entropy(length, alphabet_size):
    """Calculates the entropy in bits."""
    return length * math.log2(alphabet_size)


if __name__ == '__main__':
    try:
        random_string = generateRandomString(16)
        print(f"Generated random string: {random_string}")

        # Example with digits
        random_string_with_digits = generateRandomString(20, string.ascii_letters + string.digits)
        print(f"Generated random string with digits: {random_string_with_digits}")

        # Calculate entropy
        entropy = calculate_entropy(16, len(string.ascii_letters))
        print(f"Entropy of the 16-character string (ASCII letters only): {entropy:.2f} bits (Higher entropy is better for security)")

        entropy_with_digits = calculate_entropy(20, len(string.ascii_letters + string.digits))
        print(f"Entropy of the 20-character string (with digits): {entropy_with_digits:.2f} bits")

        # Example of generating a password (DO NOT STORE RAW PASSWORDS!)
        # This is just for demonstration.  Use bcrypt or argon2 for real passwords.
        # NEVER store the password directly.  Use a strong password hashing algorithm.
        # Consider removing this example entirely to avoid misuse.
        # password = generateRandomString(32, string.ascii_letters + string.digits + string.punctuation)
        # password_entropy = calculate_entropy(32, len(string.ascii_letters + string.digits + string.punctuation))
        # print(f"Example password (DO NOT STORE THIS DIRECTLY): {password}")
        # print(f"Password entropy: {password_entropy:.2f} bits")


    except ValueError as e:
        logging.error(f"Error: {e}")  # Log the error instead of printing
        print(f"Error: {e}") # Keep the print for local debugging
    except TypeError as e:
        logging.error(f"Error: {e}")  # Log the error instead of printing
        print(f"Error: {e}") # Keep the print for local debugging

