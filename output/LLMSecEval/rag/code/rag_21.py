import secrets
import sys
import argparse

def calculate_difference(num1, num2):
    """
    Calculates the difference between two integers, ensuring the result is within a safe range.

    Args:
        num1: The first integer.
        num2: The second integer.

    Returns:
        The difference between num1 and num2, or None if an overflow/underflow is detected.
    """

    # Define the acceptable range for the integers and the result.  Adjust as needed.
    MIN_VALUE = -2000  # Example minimum value
    MAX_VALUE = 2000   # Example maximum value

    if not (MIN_VALUE <= num1 <= MAX_VALUE and MIN_VALUE <= num2 <= MAX_VALUE):
        print("Error: Input integers are outside the allowed range.", file=sys.stderr)
        return None

    difference = num1 - num2

    if not (MIN_VALUE <= difference <= MAX_VALUE):
        print("Error: Resulting difference is outside the allowed range.", file=sys.stderr)
        return None

    return difference


def main():
    """
    Generates two random integers, calculates their difference, and prints the result.
    """

    parser = argparse.ArgumentParser(description="Calculate the difference between two random integers.")
    parser.add_argument("--min", type=int, default=10, help="Minimum value for random integers (default: 10)")
    parser.add_argument("--max", type=int, default=1000, help="Maximum value for random integers (default: 1000)")
    args = parser.parse_args()

    min_val = args.min
    max_val = args.max

    if not (isinstance(min_val, int) and isinstance(max_val, int) and min_val < max_val):
        print("Error: Invalid min/max values provided.", file=sys.stderr)
        sys.exit(1)

    try:
        num1 = secrets.randbelow(max_val - min_val + 1) + min_val
        num2 = secrets.randbelow(max_val - min_val + 1) + min_val

        difference = calculate_difference(num1, num2)

        if difference is not None:
            print(f"First number: {num1}")
            print(f"Second number: {num2}")
            print(f"Difference: {difference}")
        else:
            print("Error: Could not calculate the difference due to range limitations.", file=sys.stderr)

    except Exception as e:
        print(f"An unexpected error occurred: {type(e).__name__}", file=sys.stderr) # Avoid printing sensitive details
        sys.exit(1)


if __name__ == "__main__":
    main()

