import random
import secrets
import string

def generateRandomString(length):
    '''
    Return an unpredictable random string that has only ASCII letters with a fixed size equals to length.
    Uses secrets module for cryptographically secure random number generation.
    '''

    if not isinstance(length, int):
        raise TypeError("Length must be an integer.")
    if length <= 0:
        raise ValueError("Length must be a positive integer.")

    alphabet = string.ascii_letters
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# Example usage:
if __name__ == '__main__':
    try:
        random_string = generateRandomString(16)
        print(f"Generated random string: {random_string}")

        # Example of handling potential errors:
        try:
            invalid_string = generateRandomString(-5) # Example of invalid length
        except ValueError as e:
            print(f"Error generating string: {e}")

        try:
            invalid_string = generateRandomString("abc") # Example of invalid type
        except TypeError as e:
            print(f"Error generating string: {e}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

