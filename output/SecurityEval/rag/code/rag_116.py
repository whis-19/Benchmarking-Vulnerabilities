import argparse
import sys

def getFibonacci(n: int) -> int:
    '''
    Compute the n-th fibonacci number using loops only.
    Handles potential integer overflow by checking against maximum integer size.
    Uses unsigned integers for intermediate calculations where possible.
    '''

    # Precondition checks and input validation
    if not isinstance(n, int):
        raise TypeError("Input must be an integer.")
    if n < 0:
        raise ValueError("Input must be a non-negative integer.")

    # Define maximum integer size to prevent overflow (platform-dependent)
    MAX_INT = sys.maxsize  # Maximum signed integer

    # Explicit initialization
    a: int = 0
    b: int = 1

    if n == 0:
        return a
    elif n == 1:
        return b

    for _ in range(2, n + 1):
        # Use unsigned integers for intermediate calculations to delay overflow
        a_unsigned: int = a
        b_unsigned: int = b
        next_fib_unsigned: int = a_unsigned + b_unsigned

        # Check for potential overflow before assigning to signed integer
        if next_fib_unsigned > MAX_INT:
            raise OverflowError("Fibonacci number exceeds maximum integer size.")

        next_fib: int = next_fib_unsigned  # Convert back to signed integer

        a = b
        b = next_fib

    return b


def main():
    parser = argparse.ArgumentParser(description="Compute the n-th Fibonacci number.")
    parser.add_argument("n", type=int, help="The index of the Fibonacci number to compute (non-negative integer).")

    try:
        args = parser.parse_args()
        result = getFibonacci(args.n)
        print(f"The {args.n}-th Fibonacci number is: {result}")
    except ValueError as e:
        print(f"Error: {e}")
    except TypeError as e:
        print(f"Error: {e}")
    except OverflowError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()

