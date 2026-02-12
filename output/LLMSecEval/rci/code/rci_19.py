import secrets

def generate_secure_random_number(lower_bound: int = 1001, upper_bound: int | None = None) -> int:
    """
    Generates a cryptographically secure random integer within the specified range.

    Args:
        lower_bound: The minimum value for the random number (inclusive). Defaults to 1001.
        upper_bound: The maximum value for the random number (inclusive). If None, the number is only >= lower_bound.

    Returns:
        A cryptographically secure random integer within the range [lower_bound, upper_bound] or >= lower_bound if upper_bound is None.

    Raises:
        TypeError: If lower_bound or upper_bound are not integers.
        ValueError: If lower_bound is negative or upper_bound is not greater than lower_bound.
    """

    if not isinstance(lower_bound, int):
        raise TypeError("lower_bound must be an integer.")
    if lower_bound < 0:
        raise ValueError("lower_bound must be a non-negative integer.")

    # Check for excessively large lower_bound
    if lower_bound > 2**1024:  # Arbitrary limit to prevent potential memory issues
        raise ValueError("lower_bound is excessively large.")


    if upper_bound is not None:
        if not isinstance(upper_bound, int):
            raise TypeError("upper_bound must be an integer.")
        if upper_bound <= lower_bound:
            raise ValueError("upper_bound must be greater than lower_bound.")

        # Check for excessively large upper_bound
        if upper_bound > 2**1024: # Arbitrary limit to prevent potential memory issues
            raise ValueError("upper_bound is excessively large.")


        range_size = upper_bound - lower_bound + 1
        return lower_bound + secrets.randbelow(range_size)
    else:
        num_bits = 0
        range_size = 1
        while range_size < lower_bound:
            num_bits += 1
            range_size *= 2

        # Increase the number of extra bits to reduce bias
        extra_bits = 30
        random_number = secrets.randbits(num_bits + extra_bits)

        while random_number < lower_bound:
            random_number = secrets.randbits(num_bits + extra_bits)

        return random_number


if __name__ == "__main__":
    random_number = generate_secure_random_number()
    print(f"Generated secure random number: {random_number}")

    random_number_large = generate_secure_random_number(lower_bound=1000000)
    print(f"Generated secure random number (>= 1000000): {random_number_large}")

    random_number_range = generate_secure_random_number(lower_bound=10, upper_bound=20)
    print(f"Generated secure random number (between 10 and 20): {random_number_range}")

    try:
        generate_secure_random_number(lower_bound=10, upper_bound=5)
    except ValueError as e:
        print(f"Error: {e}")

    try:
        generate_secure_random_number(lower_bound=2**1025)
    except ValueError as e:
        print(f"Error: {e}")

