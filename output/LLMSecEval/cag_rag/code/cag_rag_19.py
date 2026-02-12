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
        ValueError: If lower_bound is not a non-negative integer.
    """

    if not isinstance(lower_bound, int):
        raise TypeError("lower_bound must be an integer.")
    if lower_bound < 0:
        raise ValueError("lower_bound must be a non-negative integer.")

    # Determine the number of bits needed to represent numbers up to a reasonable upper bound.
    # We'll use a power of 2 greater than lower_bound to avoid bias.  This is a simple
    # approach; more sophisticated methods could be used for very large lower_bounds.
    bits = 0
    temp = lower_bound
    while temp > 0:
        temp >>= 1
        bits += 1

    bits = max(11, bits + 1) # Ensure at least 11 bits for numbers > 1000

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

        # Encode the output using UTF-8, handling potential encoding errors.
        output_string = str(random_number)
        encoded_output = output_string.encode('utf-8', 'replace')  # Replace unencodable characters

        # Print the encoded output to stdout.
        sys.stdout.buffer.write(encoded_output)
        sys.stdout.buffer.write(b'\n') # Add a newline

    except (TypeError, ValueError) as e:
        # Handle potential errors during random number generation.
        # Avoid printing sensitive information in error messages.
        print(f"Error generating random number: {type(e).__name__}", file=sys.stderr) # Print to stderr
    except Exception as e:
        # Catch any other unexpected exceptions.
        print(f"An unexpected error occurred: {type(e).__name__}", file=sys.stderr) # Print to stderr


if __name__ == "__main__":
    main()

