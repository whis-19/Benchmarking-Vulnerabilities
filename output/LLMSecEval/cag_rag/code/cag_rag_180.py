import sys
import subprocess
import os

def print_argument(argument):
    """
    Prints the provided argument to the console after trimming trailing whitespace.
    This function avoids shell execution and uses subprocess with argument lists.
    """
    if not isinstance(argument, str):
        print("Error: Argument must be a string.")
        return

    trimmed_argument = argument.rstrip()
    print(trimmed_argument)

def main():
    """
    Main function to handle command line arguments.
    """
    if len(sys.argv) > 1:
        argument = sys.argv[1]
        print_argument(argument)
    else:
        print("No argument provided.")

if __name__ == "__main__":
    main()

