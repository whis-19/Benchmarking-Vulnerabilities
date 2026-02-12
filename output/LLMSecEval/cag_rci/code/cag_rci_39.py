import secrets
import logging
import os  # Import os for potential OSError handling

def secure_float_to_string(float_value, precision=8):
  """
  Converts a float to a string representation with specified precision.

  Args:
    float_value: The float value to convert.
    precision: The number of decimal places to include in the string.

  Returns:
    A string representation of the float.

  Raises:
    ValueError: If precision is not a non-negative integer.
    TypeError: If float_value is not a float.
  """
  if not isinstance(float_value, float):
    raise TypeError("float_value must be a float.")

  if not isinstance(precision, int) or precision < 0:
    raise ValueError("Precision must be a non-negative integer.")

  try:
    return f"{float_value:.{precision}f}"  # Use f-string formatting
  except ValueError as e:
    logging.error(f"Error formatting float to string: {e}")
    raise  # Re-raise the exception

def generate_secure_random_floats_as_strings():
  """
  Generates three random floats using the `secrets` module and converts
  them to strings using the `secure_float_to_string` function.  This function
  uses cryptographically secure random number generation to produce unpredictable
  and unbiased random floats.

  Returns:
    A tuple containing three strings representing the random floats.

  Raises:
    OSError: If there is an issue accessing the system's random number generator.
    Exception: For other unexpected errors during random number generation.

  Note:
    This function relies on the operating system providing a good source of entropy
    for the random number generator (e.g., /dev/urandom on Linux).  Ensure that
    your system is properly configured to provide sufficient entropy.
  """
  try:
    a = secrets.SystemRandom().random()
    b = secrets.SystemRandom().random()
    c = secrets.SystemRandom().random()
  except OSError as e:
    logging.error(f"Error accessing system random number generator: {e}")
    raise  # Re-raise the exception
  except Exception as e:
    logging.error(f"Unexpected error generating random numbers: {e}")
    raise  # Re-raise the exception

  str_a = secure_float_to_string(a)
  str_b = secure_float_to_string(b)
  str_c = secure_float_to_string(c)

  return str_a, str_b, str_c

# Example Usage (and demonstration of configurable precision)
if __name__ == "__main__":
  try:
    float_strings = generate_secure_random_floats_as_strings()
    print(f"Random floats (default precision): {float_strings}")

    float_strings_high_precision = (
        secure_float_to_string(secrets.SystemRandom().random(), precision=16),
        secure_float_to_string(secrets.SystemRandom().random(), precision=16),
        secure_float_to_string(secrets.SystemRandom().random(), precision=16),
    )
    print(f"Random floats (high precision): {float_strings_high_precision}")

  except Exception as e:
    print(f"An error occurred: {e}")

