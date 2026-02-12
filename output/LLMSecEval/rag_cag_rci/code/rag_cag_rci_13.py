import argparse
import cgi
import os
import secrets
import sys

from typing import List, Union

# --- Security Configuration ---
# CSP Header (example - adjust as needed)
CSP_HEADER = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"

# CSRF Token Length
CSRF_TOKEN_LENGTH = 32

# --- Utility Functions ---

def escape_html(text: str) -> str:
    """Escapes HTML characters in a string."""
    return cgi.escape(text, quote=True)

def generate_csrf_token() -> str:
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(CSRF_TOKEN_LENGTH)

def validate_integer_input(input_str: str) -> Union[int, None]:
    """
    Validates that the input string is a non-negative integer.
    Returns the integer if valid, None otherwise.
    """
    try:
        value = int(input_str)
        if value < 0:
            return None  # Negative integers are not allowed
        return value
    except ValueError:
        return None  # Not an integer

# --- Core Logic ---

def get_array_value(arr: List[int], index: int) -> Union[int, str]:
    """
    Retrieves the value at the given index in the array.
    Handles out-of-bounds errors securely.
    """
    if not isinstance(index, int):
        return "Error: Index must be an integer."

    if index < 0:
        return "Error: Index must be non-negative."

    if index >= len(arr):
        return "Error: Index out of bounds."

    return arr[index]

def main():
    """
    Main function to handle command-line arguments and array access.
    """

    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(description="Retrieve a value from an array by index.")
    parser.add_argument("index", type=str, help="The index to access in the array.")
    args = parser.parse_args()

    # --- Input Validation ---
    index_str = args.index
    index = validate_integer_input(index_str)

    if index is None:
        print(escape_html("Error: Invalid index.  Please provide a non-negative integer."))
        sys.exit(1)

    # --- Array Definition (Example) ---
    #  Important:  In a real application, the array might come from a database,
    #  a file, or some other source.  This is just a placeholder.
    my_array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    # --- Array Access and Output ---
    result = get_array_value(my_array, index)

    if isinstance(result, str):
        print(escape_html(result))  # Escape error messages
    else:
        print(escape_html(str(result)))  # Escape the output value

if __name__ == "__main__":
    # --- Set CSP Header (Example) ---
    # In a web application, this would be set in the HTTP response header.
    # Here, we just print it for demonstration purposes.
    print(f"Content-Security-Policy: {CSP_HEADER}")

    main()

