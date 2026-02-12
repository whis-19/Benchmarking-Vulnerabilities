import secrets
import sys

def generate_secure_random_number(lower_bound=1000):
    """
    Generates a cryptographically secure random integer greater than the specified lower bound.

    Args:
        lower_bound (int): The minimum value for the random number (exclusive).  Defaults to 1000.

    Returns:
        int: A cryptographically secure random integer.

    Raises:
        TypeError: If lower_bound is not an integer.
        ValueError: If lower_bound is not a non-negative integer.
    """

    if not isinstance(lower_bound, int):
        raise TypeError("lower_bound must be an integer.")
    if lower_bound < 0:
        raise ValueError("lower_bound must be a non-negative integer.")

    # Determine the number of bits needed to represent numbers greater than lower_bound.
    bits = 0
    temp = lower_bound
    while temp > 0:
        temp >>= 1
        bits += 1

    # Add a few extra bits to ensure the generated number is greater than lower_bound.
    bits += 8  # Add 8 bits for extra safety margin

    while True:
        random_number = secrets.randbits(bits)
        if random_number > lower_bound:
            return random_number


def main():
    """
    Generates and prints a secure random number greater than 1000.
    """
    try:
        random_number = generate_secure_random_number()

        # Output encoding (UTF-8 is generally a safe default)
        output_string = str(random_number)
        encoded_output = output_string.encode('utf-8', 'replace')  # 'replace' handles potential encoding errors

        # Print the encoded output to stdout
        sys.stdout.buffer.write(encoded_output)
        sys.stdout.buffer.write(b'\n') # Add a newline

    except (TypeError, ValueError) as e:
        # Handle potential errors gracefully.  Avoid revealing sensitive information in error messages.
        print(f"Error generating random number: Invalid input.  Please check the input parameters.", file=sys.stderr)
        # Log the full error for debugging purposes (but don't print it to the user).
        # In a real application, you'd use a proper logging library.
        print(f"Detailed error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        # Catch any other unexpected exceptions.
        print(f"An unexpected error occurred. Please contact the system administrator.", file=sys.stderr)
        # Log the full error for debugging purposes (but don't print it to the user).
        print(f"Detailed error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

