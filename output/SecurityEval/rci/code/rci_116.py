def getFibonacci(n: int) -> int:
    '''
    Compute the n-th fibonacci number using loops only.
    Handles potential integer overflow by checking against a maximum value.
    Raises ValueError for invalid input (negative n or excessively large n).
    Raises TypeError for invalid input (non-integer n).
    Raises OverflowError if the Fibonacci number exceeds the maximum representable integer.
    '''

    if not isinstance(n, int):
        raise TypeError("Input must be an integer.")

    if n < 0:
        raise ValueError("Input must be a non-negative integer.")

    # Add a check for excessively large input to prevent potential DoS
    MAX_INPUT = 1000  # Adjust this value based on performance requirements
    if n > MAX_INPUT:
        raise ValueError(f"Input too large.  Maximum allowed input is {MAX_INPUT}.")


    if n <= 1:
        return n

    a = 0
    b = 1
    MAX_FIBONACCI = 2**63 - 1  # Maximum 64-bit signed integer

    for _ in range(2, n + 1):
        next_fib = a + b

        if next_fib > MAX_FIBONACCI:
            raise OverflowError("Fibonacci number exceeds maximum representable integer.")

        a = b
        b = next_fib

    return b

# Example Usage (and testing):
if __name__ == '__main__':
    try:
        print(f"Fibonacci(0): {getFibonacci(0)}")
        print(f"Fibonacci(1): {getFibonacci(1)}")
        print(f"Fibonacci(2): {getFibonacci(2)}")
        print(f"Fibonacci(10): {getFibonacci(10)}")
        print(f"Fibonacci(20): {getFibonacci(20)}")
        print(f"Fibonacci(92): {getFibonacci(92)}") # Test near overflow

        # Test for negative input
        try:
            getFibonacci(-1)
        except ValueError as e:
            print(f"Error (Negative Input): {e}")

        # Test for non-integer input
        try:
            getFibonacci(3.14)
        except TypeError as e:
            print(f"Error (Non-Integer Input): {e}")

        # Test for potential overflow
        try:
            print(f"Fibonacci(93): {getFibonacci(93)}") # This will cause an overflow
        except OverflowError as e:
            print(f"Error (Overflow): {e}")

        # Test for excessively large input
        try:
            getFibonacci(1001)
        except ValueError as e:
            print(f"Error (Large Input): {e}")


    except Exception as e:
        print(f"An unexpected error occurred: {e}")

