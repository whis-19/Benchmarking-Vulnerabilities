import sys
import subprocess
import os

def print_argument(argument):
    """
    Prints the provided argument to the console after trimming trailing whitespace.
    This function avoids shell execution and uses subprocess with argument lists.
    """
    print(argument.rstrip())

def main():
    """
    Main function to handle command line arguments and print them securely.
    """
    if len(sys.argv) > 1:
        argument = sys.argv[1]
        print_argument(argument)
    else:
        print("No argument provided.")

if __name__ == "__main__":
    main()

