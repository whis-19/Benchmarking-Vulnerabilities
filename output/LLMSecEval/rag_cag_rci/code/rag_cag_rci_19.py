import secrets
import sys

def generate_secure_random_number(lower_bound: int = 1000) -> int:
    """
    Generates a cryptographically secure random integer greater than the specified lower bound.

    Args:
        lower_bound (int): The minimum value for the random number (exclusive).  Defaults to 1000.

    Returns:
        int: A cryptographically secure random integer greater than lower_bound.
    """

    if not isinstance(lower_bound, int):
        raise TypeError("lower_bound must be an integer.")

    if lower_bound < 0:
        raise ValueError("lower_bound must be a non-negative integer.")

    # Determine the number of bits needed to represent numbers greater than lower_bound.
    bits = lower_bound.bit_length() + 1  # Add 1 to ensure the number is *greater* than lower_bound

    while True:
        random_number = secrets.randbits(bits)
        if random_number > lower_bound:
            return random_number


def main() -> None:
    """
    Generates and prints a secure random number greater than 1000.
    """
    try:
        random_number = generate_secure_random_number()

        # Output encoding (UTF-8 is generally a safe default)
        output_string = str(random_number)
        encoded_output = output_string.encode('utf-8', 'replace')  # 'replace' handles potential encoding issues

        # Print the encoded output to stdout
        sys.stdout.buffer.write(encoded_output)
        sys.stdout.buffer.write(b'\n') # Add a newline

    except Exception as e:
        # Handle exceptions gracefully.  Avoid revealing sensitive information in error messages.
        print(f"An error occurred during random number generation or output.  Check logs for details.", file=sys.stderr)
        # Log the full error (including traceback) to a secure location (e.g., a log file)
        # import logging
        # logging.exception("Error during random number generation:") # Example using logging module
        # The logging module should be configured to write to a file with appropriate permissions.
        # Do NOT print the full error to stdout/stderr in a production environment.
        # Example of logging to a file:
        # logging.basicConfig(filename='error.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
        # logging.exception("Error during random number generation:")
        sys.exit(1)

if __name__ == "__main__":
    main()

