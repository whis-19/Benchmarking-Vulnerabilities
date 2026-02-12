import argparse
import sys

def add_offset(value: int, offset: int = 1000) -> int:
    """
    Adds a fixed offset to an integer value, with bounds checking.

    Args:
        value: The integer value to add the offset to.
        offset: The offset to add (default: 1000).

    Returns:
        The result of adding the offset to the value, or None if an overflow/underflow occurs.

    Raises:
        ValueError: If the input value is not a valid integer.
    """

    # Check if the input is an integer
    if not isinstance(value, int):
        raise ValueError("Input value must be an integer.")

    # Define the minimum and maximum allowed values for the result.
    # This depends on the expected range of the input and the offset.
    # Adjust these values based on your specific requirements.
    MIN_VALUE = -sys.maxsize - 1  # Minimum possible integer value
    MAX_VALUE = sys.maxsize  # Maximum possible integer value

    # Check for potential overflow/underflow before performing the addition.
    if value > 0 and offset > 0 and value > MAX_VALUE - offset:
        print("Error: Integer overflow detected.")
        return None  # Indicate overflow
    if value < 0 and offset < 0 and value < MIN_VALUE - offset:
        print("Error: Integer underflow detected.")
        return None  # Indicate underflow

    result = value + offset

    # Double-check the result to ensure it's within the allowed range.
    if result < MIN_VALUE or result > MAX_VALUE:
        print("Error: Integer overflow/underflow detected after addition.")
        return None  # Indicate overflow/underflow

    return result


def main():
    """
    Reads an integer from the command line, adds a fixed offset, and prints the result.
    """
    parser = argparse.ArgumentParser(description="Add a fixed offset to an integer value.")
    parser.add_argument("value", type=int, help="The integer value to add the offset to.")

    try:
        args = parser.parse_args()
        input_value = args.value

        result = add_offset(input_value)

        if result is not None:
            print(f"The result of adding the offset to {input_value} is: {result}")
        else:
            print("An error occurred during the calculation.")

    except ValueError as e:
        print(f"Error: {e}")
    except SystemExit:
        # argparse automatically calls sys.exit() if there's an error in the arguments.
        # This prevents the rest of the script from running.
        pass
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()

