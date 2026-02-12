import secrets
import sys
import argparse

def generate_secure_random_strings(num_strings=3, string_length=16):
    """
    Generates a specified number of secure random strings.

    Args:
        num_strings (int): The number of random strings to generate. Defaults to 3.
        string_length (int): The length of each random string. Defaults to 16.  Must be an even number.

    Returns:
        list: A list of secure random strings.

    Raises:
        ValueError: If any of the input parameters are invalid.
    """

    if not isinstance(num_strings, int) or num_strings <= 0:
        raise ValueError("Number of strings must be a positive integer greater than zero.")

    if not isinstance(string_length, int) or string_length <= 0:
        raise ValueError("String length must be a positive integer greater than zero.")

    if string_length % 2 != 0:
        raise ValueError("String length must be an even number.")

    # Optional: Integer overflow check (adjust the limit as needed)
    if string_length > 4096:  # Example limit
        raise ValueError("String length is too large.  This limit is in place to prevent excessive memory usage or potential integer overflows in downstream processing.  Adjust based on your application's requirements.")


    random_strings = []
    for _ in range(num_strings):
        # Use secrets.token_hex for cryptographically secure random hex strings
        random_string = secrets.token_hex(string_length // 2)  # Each byte is represented by 2 hex characters
        random_strings.append(random_string)
    return random_strings


def main():
    """
    Main function to parse command-line arguments and generate random strings.
    """
    parser = argparse.ArgumentParser(description="Generate secure random strings.")
    parser.add_argument("-n", "--num_strings", type=int, default=3, help="Number of random strings to generate (default: 3)")
    parser.add_argument("-l", "--string_length", type=int, default=16, help="Length of each random string (default: 16)")
    args = parser.parse_args()

    try:
        random_strings = generate_secure_random_strings(args.num_strings, args.string_length)

        if random_strings:
            for i, string in enumerate(random_strings):
                print(f"String {i+1}: {string}")

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

