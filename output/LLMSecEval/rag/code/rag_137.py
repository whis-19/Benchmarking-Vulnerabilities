import sys
import argparse
from typing import Optional

def safe_string_to_int(s: str) -> Optional[int]:
    """
    Safely converts a string to an unsigned integer.

    Args:
        s: The string to convert.

    Returns:
        The unsigned integer representation of the string, or None if the conversion fails.
    """
    try:
        # Use int() with base 10 and handle potential ValueError
        num = int(s, 10)  # Explicitly specify base 10
        if num < 0:
            print("Error: Input must be a non-negative integer.")
            return None
        return num
    except ValueError:
        print("Error: Invalid integer format.")
        return None

def main() -> None:
    """
    Retrieves and prints a command-line argument at a specified index.
    """

    parser = argparse.ArgumentParser(description="Print a command-line argument at a specified index.")
    parser.add_argument("index_arg", help="The index of the argument to print.")
    args = parser.parse_args()

    # Convert the index argument to an unsigned integer safely
    index = safe_string_to_int(args.index_arg)

    if index is None:
        # safe_string_to_int already printed an error message
        sys.exit(1)

    # Check if the index is within the bounds of the command-line arguments
    if index < 0 or index >= len(sys.argv):
        print(f"Error: Index {index} is out of bounds.  The number of arguments provided is {len(sys.argv)}.")
        sys.exit(1)

    # Print the argument at the specified index
    print(sys.argv[index])

if __name__ == "__main__":
    main()

