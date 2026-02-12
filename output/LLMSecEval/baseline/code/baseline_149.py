import sys
import argparse

def add_thousand(value):
  """
  Adds 1000 to the input value.  Handles potential errors gracefully.

  Args:
    value: The value to add 1000 to.  Must be convertible to an integer.

  Returns:
    The result of adding 1000 to the input value, or None if an error occurred.
  """
  try:
    num = int(value)
    result = num + 1000
    return result
  except ValueError:
    print(f"Error: Invalid input. '{value}' is not a valid integer.")
    return None
  except OverflowError:
    print(f"Error: Input value '{value}' is too large to be represented as an integer.")
    return None
  except Exception as e:
    print(f"An unexpected error occurred: {e}")
    return None


def main():
  """
  Parses command-line arguments and performs the addition.
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
    # argparse handles invalid arguments and prints help messages,
    # which can cause SystemExit.  We catch it to prevent the program
    # from crashing unexpectedly.  argparse already prints the error.
    pass
  except Exception as e:
    print(f"An unexpected error occurred during argument parsing or processing: {e}")


if __name__ == "__main__":
  main()

