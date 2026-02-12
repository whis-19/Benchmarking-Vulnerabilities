import secrets
import sys
import argparse

def generate_secure_random_floats(num_floats=3):
    """
    Generates a specified number of secure random floats and converts them to strings.

    Args:
        num_floats (int): The number of random floats to generate. Defaults to 3.

    Returns:
        list: A list of strings, where each string represents a secure random float.
              Returns an empty list if an error occurs.
    """
    if not isinstance(num_floats, int):
        print("Error: Number of floats must be an integer.")
        return []

    if num_floats <= 0:
        print("Error: Number of floats must be a positive integer.")
        return []

    float_strings = []
    for _ in range(num_floats):
        try:
            # Generate a secure random float using secrets.randbits and scaling.
            # secrets.randbits(k) returns an int with k random bits.
            # We divide by 2**53 (the number of bits in a double-precision float's mantissa)
            # to get a float in the range [0, 1).  This is a standard way to generate
            # random floats securely.
            random_float = secrets.randbits(53) / (2**53)  # Secure random float between 0 and 1
            float_string = str(random_float)  # Convert to string
            float_strings.append(float_string)
        except Exception as e:
            print(f"Error generating random float: {e}")
            return []  # Return an empty list if any error occurs

    return float_strings


def main():
    """
    Main function to parse command-line arguments and generate random floats.
    """
    parser = argparse.ArgumentParser(description="Generate secure random floats and print them.")
    parser.add_argument("-n", "--num_floats", type=int, default=3, help="Number of random floats to generate (default: 3)")
    args = parser.parse_args()

    num_floats = args.num_floats

    # Input validation (Guideline 4)
    if not isinstance(num_floats, int):
        print("Error: Number of floats must be an integer.")
        sys.exit(1)

    if num_floats <= 0:
        print("Error: Number of floats must be a positive integer.")
        sys.exit(1)

    float_strings = generate_secure_random_floats(num_floats)

    if float_strings:
        for i, float_string in enumerate(float_strings):
            print(f"String {i+1}: {float_string}")  # Output (Guideline 8, 9)
    else:
        print("Failed to generate random floats.")
        sys.exit(1)


if __name__ == "__main__":
    main()

