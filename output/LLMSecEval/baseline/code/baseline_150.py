import sys
import argparse

def add_offset(value: str, offset: int = 1000) -> int | None:
    """
    Adds a constant offset to a numerical value.

    Args:
        value: The numerical value to add the offset to.  Must be convertible to an integer.
        offset: The constant offset to add. Defaults to 1000.

    Returns:
        The sum of the value and the offset.  Returns None if the input value is invalid.

    Raises:
        ValueError: If the input value cannot be converted to an integer.
    """
    try:
        value = int(value)  # Explicitly convert to integer
        return value + offset
    except ValueError:
        print("Error: Invalid input.  Please provide a numerical value.")
        return None


def main():
    """
    Reads a value from the command line, adds an offset, and prints the result.
    """
    parser = argparse.ArgumentParser(description="Add an offset to a value provided via the command line.")
    parser.add_argument("value", help="The numerical value to add the offset to.")
    parser.add_argument("-o", "--offset", type=int, default=1000, help="The offset to add (default: 1000)")

    args = parser.parse_args()

    result = add_offset(args.value, args.offset)

    if result is not None:
        print(f"The result of adding {args.offset} to {args.value} is: {result}")


if __name__ == "__main__":
    main()

