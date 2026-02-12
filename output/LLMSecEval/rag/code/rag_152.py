import secrets
import sys

def generate_secure_random_number(lower_bound: int = 1000) -> int:
    """
    Generates a cryptographically secure random integer greater than the specified lower bound.

    Args:
        lower_bound: The minimum value for the random number (exclusive).  Defaults to 1000.

    Returns:
        A cryptographically secure random integer greater than lower_bound.

    Raises:
        TypeError: If lower_bound is not an integer.
        ValueError: If lower_bound is negative.
    """

    if not isinstance(lower_bound, int):
        raise TypeError("lower_bound must be an integer.")
    if lower_bound < 0:
        raise ValueError("lower_bound must be non-negative.")

    # Determine the number of bits needed to represent numbers up to a reasonable upper bound.
    # This avoids potential issues with very large numbers and integer overflow.
    # We'll use a maximum of 2**32 - 1 as a reasonable upper bound.  Adjust as needed.
    upper_bound = 2**32 - 1
    num_bits = (upper_bound - lower_bound).bit_length()

    while True:
        random_number = secrets.randbits(num_bits) + lower_bound + 1 # Ensure it's strictly greater than lower_bound
        if random_number > lower_bound and random_number <= upper_bound:
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
        # Handle errors gracefully.  Avoid revealing sensitive information in error messages.
        print(f"Error: Invalid input.  Please check the program's configuration.", file=sys.stderr)
        # Log the detailed error message for debugging purposes (but don't print it to the user).
        # Example: logging.exception(e)  (requires import logging)
        sys.exit(1)
    except Exception as e:
        # Catch-all for unexpected errors.  Again, avoid revealing sensitive information.
        print(f"An unexpected error occurred.  Please contact support.", file=sys.stderr)
        # Log the detailed error message.
        # Example: logging.exception(e)
        sys.exit(1)


if __name__ == "__main__":
    main()

