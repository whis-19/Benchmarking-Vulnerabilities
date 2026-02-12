import secrets
import sys
import argparse

MAX_STRING_LENGTH = 1024  # Example maximum length

def generate_secure_random_strings(num_strings=3, string_length=16):
    """
    Generates a specified number of secure random strings.

    Args:
        num_strings (int): The number of random strings to generate. Defaults to 3.
        string_length (int): The length of each random string. Defaults to 16.

    Returns:
        list: A list of secure random strings.

    Raises:
        ValueError: If num_strings or string_length are not positive integers or if string_length exceeds MAX_STRING_LENGTH.
    """

    if not isinstance(num_strings, int) or num_strings <= 0:
        raise ValueError("Number of strings must be a positive integer greater than zero.")

    if not isinstance(string_length, int) or string_length <= 0:
        raise ValueError("String length must be a positive integer greater than zero.")

    if string_length > MAX_STRING_LENGTH:
        raise ValueError(f"String length cannot exceed {MAX_STRING_LENGTH}.")

    # Integer overflow check (very unlikely, but possible)
    if string_length // 2 > MAX_STRING_LENGTH:
        raise OverflowError("String length is too large, potential integer overflow.")


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
    sys.stdout.reconfigure(encoding='utf-8')  # Ensure UTF-8 output

    parser = argparse.ArgumentParser(description="Generate secure random strings.")
    parser.add_argument("-n", "--num_strings", type=int, default=3, help="Number of random strings to generate (default: 3)")
    parser.add_argument("-l", "--string_length", type=int, default=16, help="Length of each random string (default: 16)")
    args = parser.parse_args()


    try:
        random_strings = generate_secure_random_strings(args.num_strings, args.string_length)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except OverflowError as e:
        print(f"Error: {e}")
        sys.exit(1)

    if random_strings:
        for i, string in enumerate(random_strings):
            print(f"String {i+1}: {string}")  # Output encoding is handled by the terminal

if __name__ == "__main__":
    main()

