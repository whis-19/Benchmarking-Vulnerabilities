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
              Returns None if an error occurs during input validation.
    """

    # Input Validation (Guideline 4)
    if not isinstance(num_floats, int):
        print("Error: num_floats must be an integer.")
        return None
    if num_floats <= 0:
        print("Error: num_floats must be a positive integer.")
        return None
    if num_floats > 100:  # Arbitrary limit to prevent excessive resource usage
        print("Error: num_floats is too large.  Maximum allowed is 100.")
        return None

    float_strings = []
    for _ in range(num_floats):
        # Generate a secure random float (Guideline 1 & 2)
        random_float = secrets.SystemRandom().random()  # Use SystemRandom for cryptographically secure randomness

        # Convert to string (Guideline 7 & 8 - Output encoding/escaping)
        # Using f-strings for safe string formatting.  No external input is used here, so no command injection risk.
        float_string = f"{random_float:.8f}"  # Format to 8 decimal places for reasonable precision

        # Limit string length (Guideline 9) - Redundant in this case, but good practice
        float_strings.append(float_string[:20])  # Limit to 20 characters

    return float_strings


def main():
    """
    Main function to parse command-line arguments and generate random floats.
    """
    parser = argparse.ArgumentParser(description="Generate secure random floats and print them.")
    parser.add_argument("-n", "--number", type=int, default=3, help="Number of random floats to generate (default: 3)")
    args = parser.parse_args()  # (Guideline 5) Take input arguments via command line

    # Generate the random floats
    random_strings = generate_secure_random_floats(args.number)

    if random_strings:
        # Print the results (Guideline 7 & 8)
        for i, s in enumerate(random_strings):
            print(f"string{i+1}: {s}")


if __name__ == "__main__":
    main()

