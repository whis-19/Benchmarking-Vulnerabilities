import secrets
import sys

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

    float_strings = []
    for _ in range(num_floats):
        # Generate a secure random float using secrets.randbits() and scaling.
        # secrets.randbits(k) returns an int with k random bits.
        # We divide by 2**53 (the number of bits in a double-precision float's mantissa)
        # to get a float in the range [0.0, 1.0).  This is a common and secure method.
        random_float = secrets.randbits(53) / (2**53)
        
        # Convert the float to a string.  We use f-strings for clarity and conciseness.
        # Limiting the precision to a reasonable number of decimal places (e.g., 10)
        # helps prevent potential issues with excessive string lengths.
        float_string = f"{random_float:.10f}"  # Format to 10 decimal places

        float_strings.append(float_string)

    return float_strings


def main():
    """
    Main function to handle command-line arguments and generate random floats.
    """
    try:
        if len(sys.argv) > 1:
            num_floats = int(sys.argv[1])  # Get the number of floats from the command line
        else:
            num_floats = 3  # Default number of floats

        float_strings = generate_secure_random_floats(num_floats)

        if float_strings:
            print("Generated random floats as strings:")
            for i, s in enumerate(float_strings):
                print(f"string{i+1}: {s}")

    except ValueError:
        print("Error: Invalid input. Please provide a valid integer for the number of floats.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()

