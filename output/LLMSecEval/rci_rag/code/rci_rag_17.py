import argparse
import sys
import math  # Import math for potential future optimizations (unused, but kept for potential future use)


OFFSET = 1000
"""The fixed offset to be added to the input value."""


def add_offset(value_str):
    """
    Adds a fixed offset to an integer value provided as a string.

    This function validates the input to prevent integer overflow and underflow.
    It handles inputs up to sys.maxsize and down to -sys.maxsize - 1.

    Args:
        value_str: The string representation of the integer value.

    Returns:
        The sum of the value and the offset, or None if an error occurs.
    """

    try:
        # Input validation: Check if the input is a valid integer
        value = int(value_str)

        # Input validation: Check for potential overflow/underflow before addition
        # Note: sys.maxsize represents the largest positive integer that can be represented.
        # -sys.maxsize - 1 is the minimum integer.
        if value > sys.maxsize - OFFSET:
            print("Error: Potential overflow detected.  Input value too large.")
            return None
        if value < -sys.maxsize - 1 + OFFSET:  # Corrected underflow check
            print("Error: Potential underflow detected. Input value too small.")
            return None

        result = value + OFFSET
        return result

    except ValueError:
        print("Error: Invalid input. Please provide an integer.")
        return None
    except OverflowError:
        # OverflowError is unlikely here because we explicitly check for potential
        # overflow *before* performing the addition.  It's included for
        # completeness and to handle unexpected scenarios (e.g., if the input
        # value is already very close to sys.maxsize).
        print("Error: Integer overflow occurred.")  # More specific error message
        return None


def main():
    """
    Parses the command line arguments and calls the add_offset function.
    """
    parser = argparse.ArgumentParser(description="Adds an offset to an integer value.")
    parser.add_argument("value", type=str, help="The integer value to add the offset to.")  # Keep as string for consistent error handling

    args = parser.parse_args()

    result = add_offset(args.value)

    if result is not None:
        print(f"The result is: {result}")


if __name__ == "__main__":
    main()

