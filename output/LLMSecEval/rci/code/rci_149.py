import sys
import argparse

def add_thousand(value):
  """
  Adds 1000 to the input value.  Handles potential errors gracefully.

  Args:
    value: The value to add 1000 to.  Must be convertible to an integer.

  Returns:
    The input value plus 1000, or None if an error occurred.
  """
  try:
    if not isinstance(value, str):
      raise ValueError("Input must be a string.")

    if not value.isdigit():
      print("Error: Input must contain only digits.")
      return None

    num = int(value)

    # Check for potential overflow BEFORE adding
    if num > 2147482647:  # Max int32 - 1000
      print("Error: Input number is too large to add 1000 without overflow.")
      return None

    result = num + 1000
    return result
  except ValueError:
    print(f"Error: Invalid input. '{value}' is not a valid integer.")
    return None
  except Exception as e:
    print(f"An unexpected error occurred: {e}")
    return None


def main():
  """
  Parses command-line arguments and calls the add_thousand function.
  """
  parser = argparse.ArgumentParser(description="Adds 1000 to a number provided as a command-line argument.")
  parser.add_argument("number", help="The number to add 1000 to.")

  try:
    args = parser.parse_args()
    input_value = args.number

    result = add_thousand(input_value)

    if result is not None:
      print(f"The result of adding 1000 to {input_value} is: {result}")

  except SystemExit:
    # argparse automatically handles invalid arguments and prints help messages,
    # which can cause a SystemExit exception.  We catch it here to prevent
    # the program from crashing if the user provides invalid input.
    pass  # argparse already printed the error message.


if __name__ == "__main__":
  main()

