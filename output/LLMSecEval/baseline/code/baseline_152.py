import secrets

def generate_secure_random_number(lower_bound=1001):
  """
  Generates a cryptographically secure random integer greater than or equal to the specified lower bound.

  Args:
    lower_bound: The minimum value for the random number (inclusive).  Defaults to 1001.

  Returns:
    A cryptographically secure random integer greater than or equal to lower_bound.
  """

  if not isinstance(lower_bound, int):
    raise TypeError("lower_bound must be an integer.")
  if lower_bound < 0:
    raise ValueError("lower_bound must be a non-negative integer.")


  # Determine the number of bits needed to represent the range.
  num_bits = (lower_bound - 1).bit_length() + 1  # +1 to ensure it's *at least* that many bits

  while True:
    random_number = secrets.randbits(num_bits)
    if random_number >= lower_bound:
      return random_number


if __name__ == "__main__":
  try:
    random_number = generate_secure_random_number()
    print(f"Generated secure random number: {random_number}")

    # Example with a different lower bound:
    random_number_large = generate_secure_random_number(lower_bound=10000)
    print(f"Generated secure random number (>= 10000): {random_number_large}")

  except (TypeError, ValueError) as e:
    print(f"Error: {e}")

