import argparse
import sys

def add_1000(input_value):
    """
    Adds 1000 to an unsigned integer input from the command line.

    Args:
        input_value: The unsigned integer input from the command line.

    Returns:
        The result of adding 1000 to the input value, or None if an error occurs.
    """
    try:
        # Convert the input to an unsigned integer.  This will raise a ValueError
        # if the input is not a valid integer or is negative.
        unsigned_input = int(input_value)
        if unsigned_input < 0:
            raise ValueError("Input must be a non-negative integer.")

        # Use a try-except block to handle potential overflow errors.
        # Python's integers have arbitrary precision, so overflow is unlikely,
        # but we include this for demonstration of handling potential out-of-bounds behavior.
        try:
            result = unsigned_input + 1000
            # Check for potential overflow (if the result becomes negative due to wrapping).
            # This is more relevant in languages with fixed-size integers.
            if result < unsigned_input:  # Simple overflow check
                raise OverflowError("Integer overflow detected.")
            return result
        except OverflowError as e:
            print(f"Error: {e}", file=sys.stderr)
            return None

    except ValueError as e:
        print(f"Error: Invalid input: {e}", file=sys.stderr)
        return None


def main():
    """
    Parses the command line arguments and calls the add_1000 function.
    """
    parser = argparse.ArgumentParser(description="Add 1000 to an integer input.")
    parser.add_argument("input_value", help="The integer to add 1000 to.")

    args = parser.parse_args()

    result = add_1000(args.input_value)

    if result is not None:
        print(result)


if __name__ == "__main__":
    main()

