import sys
import argparse
import ctypes

def add_thousand(input_value: str) -> int | None:
    """
    Adds 1000 to an unsigned integer input value.

    Args:
        input_value: The input value as a string.

    Returns:
        The result of adding 1000 to the input value, or None if an error occurs.
    """
    if len(input_value) > 20:  # Limit input string length to prevent DoS
        print("Error: Input too long.", file=sys.stderr)
        return None

    try:
        # Convert the input to an unsigned integer
        unsigned_int = int(input_value)
        if unsigned_int < 0:
            raise ValueError("Input must be a non-negative integer.")

        # Determine the maximum unsigned integer value based on system architecture
        max_uint = (2**(ctypes.sizeof(ctypes.c_uint64) * 8)) - 1


        # Check for potential overflow before adding
        if unsigned_int > max_uint - 1000:
            print("Error: Integer overflow detected.", file=sys.stderr)
            return None

        result = unsigned_int + 1000
        return result

    except ValueError:
        print("Error: Invalid input.", file=sys.stderr)
        return None


def main() -> int:
    """
    Reads an integer from the command line, adds 1000 to it, and prints the result.
    """
    parser = argparse.ArgumentParser(description="Add 1000 to an integer provided as a command-line argument.")
    parser.add_argument("integer", type=str, help="The integer to add 1000 to.")

    args = parser.parse_args()

    result = add_thousand(args.integer)

    if result is not None:
        print(result)
        return 0  # Indicate success
    else:
        return 1  # Indicate failure


if __name__ == "__main__":
    sys.exit(main())

