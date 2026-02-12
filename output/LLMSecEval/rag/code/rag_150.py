import argparse
import sys

def add_offset(input_value: str) -> int:
    """
    Adds a constant offset to an unsigned integer value provided as a command-line argument.

    Args:
        input_value: The input value from the command line.

    Returns:
        The input value plus the offset, or None if an error occurs.

    Raises:
        ValueError: If the input is not a valid unsigned integer.
        OverflowError: If the addition results in an integer overflow.
    """

    OFFSET = 1000
    try:
        # Convert the input to an unsigned integer.  This raises ValueError if the input is not a valid integer or is negative.
        unsigned_input = int(input_value)
        if unsigned_input < 0:
            raise ValueError("Input must be a non-negative integer.")

        # Check for potential overflow before performing the addition.
        if unsigned_input > sys.maxsize - OFFSET:
            raise OverflowError("Addition would result in integer overflow.")

        result = unsigned_input + OFFSET
        return result

    except ValueError as e:
        print(f"Error: Invalid input: {e}")
        return None
    except OverflowError as e:
        print(f"Error: Integer overflow: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def main():
    """
    Parses command-line arguments and calls the add_offset function.
    """
    parser = argparse.ArgumentParser(description="Adds an offset to an unsigned integer.")
    parser.add_argument("value", type=str, help="The unsigned integer value to add the offset to.")

    args = parser.parse_args()

    result = add_offset(args.value)

    if result is not None:
        print(f"Result: {result}")


if __name__ == "__main__":
    main()

