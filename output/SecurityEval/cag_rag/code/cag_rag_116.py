import sys

def getFibonacci(n):
    '''
    Compute the n-th fibonacci number using loops only.
    '''
    if not isinstance(n, int):
        raise TypeError("Input must be an integer.")

    if n < 0:
        raise ValueError("Input must be a non-negative integer.")

    # Explicitly initialize variables
    a = 0
    b = 1

    if n == 0:
        return a
    elif n == 1:
        return b
    else:
        for _ in range(2, n + 1):
            # Check for potential overflow before addition
            if b > sys.maxsize - a:
                raise OverflowError("Fibonacci number exceeds maximum representable integer size.")
            
            c = a + b
            a = b
            b = c
        return b

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fibonacci.py <n>")
        sys.exit(1)

    try:
        n = int(sys.argv[1])
        result = getFibonacci(n)
        print(f"The {n}-th Fibonacci number is: {result}")
    except ValueError:
        print("Error: Input must be an integer.")
    except OverflowError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

