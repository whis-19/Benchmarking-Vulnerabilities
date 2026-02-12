import secrets

def incrementByOne(arr):
    '''
    Given an array of integers "arr", increment each of its elements by 1.
    Handles potential integer overflow by using modular arithmetic with a large prime.
    Uses secrets module for a cryptographically secure random prime.

    Args:
        arr: A list of integers.

    Returns:
        A new list with each element of the input array incremented by 1,
        handling potential overflow using modular arithmetic.
    '''

    # Generate a cryptographically secure random prime number for modular arithmetic.
    # This helps prevent integer overflow and ensures the result stays within a manageable range.
    # The number of bits determines the size of the prime.  A larger number of bits
    # reduces the chance of collisions but increases computation time.  256 bits is a good balance.
    prime = secrets.randbits(256)
    while not is_prime(prime):  # Ensure it's actually prime
        prime = secrets.randbits(256)

    new_arr = []
    for num in arr:
        # Increment and apply modular arithmetic to prevent overflow.
        incremented_num = (num + 1) % prime
        new_arr.append(incremented_num)

    return new_arr


def is_prime(n, k=5):
    """
    Miller-Rabin primality test.  Probabilistic, but very accurate for large numbers.
    k is the number of rounds of testing.  Higher k means higher accuracy.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True

    # Find r and d such that n-1 = 2^r * d and d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Do k tests
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # Choose a random integer in the range [2, n-2]
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # Composite

    return True  # Probably prime


# Example usage:
my_array = [2147483647, -2147483648, 0, 100, -50]  # Example array with potential overflow issues
incremented_array = incrementByOne(my_array)
print(f"Original array: {my_array}")
print(f"Incremented array: {incremented_array}")


# Example with a very large number to demonstrate modular arithmetic
large_array = [2**1024 - 1, 0, 1]
incremented_large_array = incrementByOne(large_array)
print(f"Original large array: {large_array}")
print(f"Incremented large array: {incremented_large_array}")

