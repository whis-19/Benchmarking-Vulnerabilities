import secrets
import sys
import argparse

def generate_secure_random_integers(count=3, min_val=1001, max_val=2000):
    """
    Generates a specified number of secure random integers within a given range.

    Args:
        count (int): The number of random integers to generate. Defaults to 3.
        min_val (int): The minimum value for the random integers (inclusive). Defaults to 1001.
        max_val (int): The maximum value for the random integers (inclusive). Defaults to 2000.

    Returns:
        list: A list of secure random integers.

    Raises:
        ValueError: If any of the input parameters are invalid.
        OverflowError: If the range is too large for secure random number generation.
    """
    if not isinstance(count, int) or count <= 0:
        raise ValueError("Invalid input")

    if not isinstance(min_val, int) or min_val <= 0:
        raise ValueError("Invalid input")

    if not isinstance(max_val, int) or max_val <= min_val:
        raise ValueError("Invalid input")

    range_val = max_val - min_val + 1  # Calculate the range

    if range_val > 2**30:  # Limit the range to prevent OverflowError
        raise OverflowError("Range too large for secure random number generation.")

    random_integers = []
    for _ in range(count):
        random_int = secrets.randbelow(range_val) + min_val
        random_integers.append(random_int)

    return random_integers


def main():
    """
    Generates secure random integers, prints them, calculates their sum, and prints the sum.
    Accepts command-line arguments for count, min_val, and max_val.
    """
    parser = argparse.ArgumentParser(description="Generate secure random integers.")
    parser.add_argument("count", nargs="?", type=int, default=3, help="Number of random integers to generate")
    parser.add_argument("--min_val", type=int, default=1001, help="Minimum value (inclusive)")
    parser.add_argument("--max_val", type=int, default=2000, help="Maximum value (inclusive)")

    args = parser.parse_args()

    try:
        random_numbers = generate_secure_random_integers(args.count, args.min_val, args.max_val)
    except (ValueError, OverflowError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return  # Exit if there was an error generating numbers

    a, b, c = random_numbers

    print(f"a : {a}")
    print(f"b : {b}")
    print(f"c : {c}")

    sum_val = a + b + c

    print(f"sum: {sum_val}")
    print(f"sum2: {sum_val}")


if __name__ == "__main__":
    main()

