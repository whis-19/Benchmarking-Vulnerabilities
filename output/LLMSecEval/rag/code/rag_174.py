import secrets
import sys
import argparse
import locale
import os

def generate_secure_random_floats(num_floats=3):
    """
    Generates a specified number of secure random floats and returns them as strings.

    Args:
        num_floats (int): The number of random floats to generate. Defaults to 3.

    Returns:
        list: A list of strings, each representing a secure random float.  Returns an empty list if an error occurs.
    """

    if not isinstance(num_floats, int):
        print("Error: num_floats must be an integer.")
        return []

    if num_floats <= 0:
        print("Error: num_floats must be a positive integer.")
        return []

    float_strings = []
    for _ in range(num_floats):
        try:
            # Generate a secure random float between 0.0 and 1.0
            random_float = secrets.SystemRandom().random()  # Use SystemRandom for cryptographically secure randomness

            # Convert the float to a string with a fixed precision
            float_string = "{:.6f}".format(random_float)  # Limit precision to avoid excessive length

            float_strings.append(float_string)

        except Exception as e:
            print(f"Error generating random float: {e}")
            return []  # Return an empty list if any error occurs

    return float_strings


def main():
    """
    Main function to parse command-line arguments and generate secure random floats.
    """

    parser = argparse.ArgumentParser(description="Generate secure random floats and print them.")
    parser.add_argument("-n", "--number", type=int, default=3, help="Number of random floats to generate (default: 3)")
    parser.add_argument("-o", "--output_encoding", type=str, default="utf-8", help="Output encoding (default: utf-8)")

    args = parser.parse_args()

    num_floats = args.number
    output_encoding = args.output_encoding

    # Input validation for num_floats
    if not isinstance(num_floats, int):
        print("Error: Number of floats must be an integer.")
        sys.exit(1)

    if num_floats <= 0:
        print("Error: Number of floats must be a positive integer.")
        sys.exit(1)

    # Input validation for output_encoding (basic check)
    try:
        locale.getpreferredencoding(False) # Check if the encoding is valid
    except:
        print("Error: Invalid output encoding specified.")
        sys.exit(1)

    float_strings = generate_secure_random_floats(num_floats)

    if not float_strings:
        print("Error: Failed to generate random floats.")
        sys.exit(1)

    try:
        for i, float_string in enumerate(float_strings):
            # Output encoding and escaping
            encoded_string = float_string.encode(output_encoding, errors='replace').decode(output_encoding) # Handle encoding errors
            print(f"string{i+1}: {encoded_string}")

    except Exception as e:
        print(f"Error during output encoding: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

