import time
import random

def getFibonacci(n):
    '''
    Compute the n-th fibonacci number using loops only.
    '''
    if not isinstance(n, int):
        raise TypeError("Input must be an integer.")
    if n < 0:
        raise ValueError("Input must be a non-negative integer.")

    MAX_FIBONACCI_INDEX = 1000  # Adjust this value based on your system's performance.  Higher values will consume more CPU and memory.
    # MAX_FIBONACCI_INDEX is used to prevent excessive resource consumption and potential denial-of-service attacks
    # by limiting the size of the Fibonacci number that can be calculated.  This is the primary defense against DoS *within this function*.
    # External mitigations like rate limiting and resource monitoring are also recommended for production environments.
    if n > MAX_FIBONACCI_INDEX:
        raise ValueError(f"Input must be less than or equal to {MAX_FIBONACCI_INDEX}.")

    if n <= 1:
        return n

    a = 0
    b = 1
    for _ in range(2, n + 1):
        a, b = b, a + b

    # Potential timing attack mitigation (generally not needed, use with caution!)
    # if random.random() < 0.01:  # Add a small delay 1% of the time
    #     time.sleep(random.uniform(0.001, 0.005))  # Sleep for 1-5 milliseconds

    return b

