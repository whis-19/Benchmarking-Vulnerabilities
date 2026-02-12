import sys

def getFibonacci(n):
    '''
    Compute the n-th fibonacci number using loops only.
    Handles potential integer overflow by checking against maximum integer size.
    '''

    # Initialize variables
    a = 0
    b = 1

    # Check for valid input
    if not isinstance(n, int):
        raise TypeError("Input must be an integer.")
    if n < 0:
        raise ValueError("Input must be a non-negative integer.")

    # Handle base cases
    if n == 0:
        return 0
    elif n == 1:
        return 1

    # Calculate Fibonacci number iteratively
    for _ in range(2, n + 1):
        # Check for potential overflow before addition
        if b > (sys.maxsize - a):
            raise OverflowError("Fibonacci number exceeds maximum integer size.")

        a, b = b, a + b

    return b

if __name__ == "__main__":
    # Get input from command line
    if len(sys.argv) != 2:
        print("Usage: python fibonacci.py <n>")
        sys.exit(1)

    try:
        n = int(sys.argv[1])
    except ValueError:
        print("Error: Input must be an integer.")
        sys.exit(1)

    try:
        result = getFibonacci(n)
        print(f"The {n}-th Fibonacci number is: {result}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except OverflowError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except TypeError as e:
        print(f"Error: {e}")
        sys.exit(1)

