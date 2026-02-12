import sys
import argparse

def add_offset(value, offset=1000):
    """
    Adds a constant offset to a numerical value.

    Args:
        value: The numerical value to add the offset to.  Must be convertible to an integer.
        offset: The constant offset to add. Defaults to 1000.

    Returns:
        The sum of the value and the offset.

    Raises:
        ValueError: If the input value cannot be converted to an integer.
        OverflowError: If integer overflow occurs.
    """
    try:
        value = int(value)
    except ValueError:
        raise ValueError("Input value must be a valid integer.")

    result = value + offset

    # Check for overflow/underflow based on system's integer size
    if result > sys.maxsize:
        raise OverflowError("Integer overflow detected.")
    if result < -sys.maxsize - 1:  # Minimum integer value
        raise OverflowError("Integer underflow detected.")

    return result


def main():
    """
    Reads a value from the command line, adds an offset, and prints the result.
    """
    parser = argparse.ArgumentParser(description="Add an offset to a command-line argument.")
    parser.add_argument("input_value", help="The numerical value to add the offset to.")
    parser.add_argument("--offset", type=int, default=1000, help="The offset to add (default: 1000)")

    args = parser.parse_args()

    # Input Validation: Check length before conversion
    if len(args.input_value) > 20:  # Adjust the length as needed
        print("Error: Input value is too large.")
        sys.exit(1)  # Exit with an error code

    try:
        result = add_offset(args.input_value, args.offset)
        print(f"The result is: {result}")
    except (ValueError, OverflowError) as e:
        print(f"Error: {e}")
        sys.exit(1) # Exit with an error code


if __name__ == "__main__":
    main()

