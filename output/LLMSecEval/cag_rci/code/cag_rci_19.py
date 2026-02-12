import secrets
import math
import os  # For checking entropy (Linux example)

class SecureRandomError(ValueError):
    """Base class for exceptions in this module."""
    pass

class InvalidLowerBoundError(SecureRandomError):
    pass

class InvalidUpperBoundError(SecureRandomError):
    pass


def generate_secure_random_number(lower_bound=1001, upper_bound=None):
    """
    Generates a cryptographically secure random integer within a specified range.

    Args:
        lower_bound: The minimum value for the random number (inclusive).  Defaults to 1001.
        upper_bound: The maximum value for the random number (inclusive). If None, only a lower bound is enforced.

    Returns:
        A cryptographically secure random integer within the specified range.

    Raises:
        TypeError: If lower_bound or upper_bound are not integers.
        InvalidLowerBoundError: If lower_bound is negative.
        InvalidUpperBoundError: If upper_bound is less than or equal to lower_bound.
    """

    if not isinstance(lower_bound, int):
        raise TypeError("lower_bound must be an integer.")
    if lower_bound < 0:
        raise InvalidLowerBoundError("lower_bound must be a non-negative integer.")

    if upper_bound is not None:
        if not isinstance(upper_bound, int):
            raise TypeError("upper_bound must be an integer.")
        if upper_bound <= lower_bound:
            raise InvalidUpperBoundError("upper_bound must be greater than lower_bound.")

        range_size = upper_bound - lower_bound + 1  # Calculate the size of the range
        # return lower_bound + secrets.choice(range(range_size)) # Use secrets.choice for perfect uniformity (potentially slower).  Each number in the range has an equal probability of being chosen.

        num_bits = math.ceil(math.log2(range_size))  # Calculate the number of bits needed

        while True:
            random_number = secrets.randbits(int(num_bits))
            if random_number < range_size:
                return lower_bound + random_number  # Shift the number to the desired range
    else:
        # Only lower bound is specified
        num_bits = math.ceil(math.log2(lower_bound))
        while True:
            random_number = secrets.randbits(int(num_bits + 10))  # Add 10 extra bits
            if random_number >= lower_bound:
                return random_number


def generate_secure_random_bit():
    """Generates a cryptographically secure random bit (0 or 1)."""
    return secrets.randbits(1)


if __name__ == "__main__":
    # Example of checking entropy (Linux)
    if os.name == 'posix':
        try:
            with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
                entropy = int(f.read().strip())
                print(f"Available entropy: {entropy}")
                if entropy < 100:  # Adjust threshold as needed
                    print("Warning: Low entropy. Consider using haveged or rng-tools.")
        except FileNotFoundError:
            print("Entropy check not available on this system.")

    random_number = generate_secure_random_number()
    print(f"Generated secure random number: {random_number}")

    random_bit = generate_secure_random_bit()
    print(f"Generated secure random bit: {random_bit}")

    # Example with a different lower bound:
    random_number_large = generate_secure_random_number(lower_bound=100000)
    print(f"Generated secure random number (>= 100000): {random_number_large}")

    # Example with a range:
    random_number_range = generate_secure_random_number(lower_bound=1000, upper_bound=2000)
    print(f"Generated secure random number between 1000 and 2000: {random_number_range}")

