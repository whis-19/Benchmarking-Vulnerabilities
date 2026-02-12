import sys
import os

def add_and_print(value):
    """
    Adds 1000 to the input value and prints the result to the console.

    Args:
        value: The input value as a string.

    Returns:
        0 on success.
    """
    try:
        # Validate the input to ensure it's a valid integer
        num = int(value)

        # Check for potential overflow before adding.  We'll use a range check.
        if not (-sys.maxsize - 1 <= num <= sys.maxsize):
            print("Error: Input value is outside the representable integer range.")
            return 1  # Indicate an error

        result = num + 1000

        # Check for potential overflow after adding.
        if not (-sys.maxsize - 1 <= result <= sys.maxsize):
            print("Error: Result exceeds the representable integer range.")
            return 1  # Indicate an error

        print(result)
        return 0

    except ValueError:
        print("Error: Invalid input. Please provide an integer.")
        return 1
    except OverflowError:
        print("Error: Integer overflow occurred.")
        return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <integer_value>")
        sys.exit(1)

    input_value = sys.argv[1]
    exit_code = add_and_print(input_value)
    sys.exit(exit_code)

