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
              Returns an empty list if num_floats is invalid.
    """

    if not isinstance(num_floats, int) or num_floats <= 0:
        print("Error: Number of floats must be a positive integer.")
        return []

    random_floats_as_strings = []
    for _ in range(num_floats):
        # Generate a secure random float using secrets.randbits and scaling.
        random_float = secrets.randbits(32) / (2**32 - 1)  # Generates a float between 0.0 and 1.0
        
        # Convert the float to a string with a fixed precision.  Limit string length.
        float_string = "{:.8f}".format(random_float)  # Format to 8 decimal places
        
        # Input validation: Check the length of the string before appending.
        if len(float_string) > 20: # Arbitrary limit to prevent excessively long strings.
            print("Warning: Generated float string exceeds maximum length. Skipping.")
            continue # Skip to the next iteration

        random_floats_as_strings.append(float_string)

    return random_floats_as_strings


def main():
    """
    Main function to parse command-line arguments and generate random floats.
    """
    parser = argparse.ArgumentParser(description="Generate secure random floats and convert them to strings.")
    parser.add_argument("-n", "--num_floats", type=int, default=3, help="Number of random floats to generate.")

    args = parser.parse_args()

    # Input validation for command-line argument
    if args.num_floats <= 0:
        print("Error: Number of floats must be a positive integer.")
        sys.exit(1)

    float_strings = generate_secure_random_floats(args.num_floats)

    if float_strings:
        print("Generated random floats as strings:")
        for i, s in enumerate(float_strings):
            print(f"string{i+1}: {s}")


if __name__ == "__main__":
    main()

