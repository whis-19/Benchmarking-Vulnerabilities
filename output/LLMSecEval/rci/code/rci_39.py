import secrets
import sys

def float_to_string(float_value):
  """
  Converts a float to a string representation with controlled precision.

  Args:
    float_value: The float value to convert.

  Returns:
    A string representation of the float with 16 decimal places.
  """
  return f"{float_value:.16f}"  # Explicitly control precision

def generate_secure_random_floats_as_strings():
  """
  Generates three random floats using secrets.SystemRandom and converts them to strings.

  Returns:
    A tuple containing three strings representing the random floats.
  """

  # Use secrets.SystemRandom for cryptographically secure random number generation.
  random_generator = secrets.SystemRandom()

  float_a = random_generator.random()
  float_b = random_generator.random()
  float_c = random_generator.random()

  str_a = float_to_string(float_a)
  str_b = float_to_string(float_b)
  str_c = float_to_string(float_c)

  return str_a, str_b, str_c


def generate_secure_random_floats_in_range(min_val, max_val):
    """Generates three secure random floats within a specified range and returns them as strings.

    Args:
        min_val: The minimum value of the range (inclusive).
        max_val: The maximum value of the range (exclusive).

    Returns:
        A tuple containing three strings representing the random floats within the specified range.

    Raises:
        ValueError: If min_val is not less than max_val.

    # This function generates random floats for use in [specific application].
    # It is assumed that an attacker cannot directly observe the generated floats
    # or the internal state of the random number generator.  If these assumptions
    # are not valid, a more robust security analysis is required.
    """
    if min_val >= max_val:
        raise ValueError("min_val must be less than max_val")

    random_generator = secrets.SystemRandom()
    float_a = min_val + (max_val - min_val) * random_generator.random()
    float_b = min_val + (max_val - min_val) * random_generator.random()
    float_c = min_val + (max_val - min_val) * random_generator.random()

    str_a = float_to_string(float_a)
    str_b = float_to_string(float_b)
    str_c = float_to_string(float_c)

    return str_a, str_b, str_c


if __name__ == "__main__":
  str_a, str_b, str_c = generate_secure_random_floats_as_strings()

  print(f"String a: {str_a}")
  print(f"String b: {str_b}")
  print(f"String c: {str_c}")


  str_x, str_y, str_z = generate_secure_random_floats_in_range(10.0, 20.0)
  print(f"String x (range 10-20): {str_x}")
  print(f"String y (range 10-20): {str_y}")
  print(f"String z (range 10-20): {str_z}")

