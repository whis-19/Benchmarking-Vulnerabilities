import cgi
import os
import re
import html

# --- Security Hardening ---

# 1. Input Validation and Sanitization:
def validate_index(index_str, array_length):
    """
    Validates that the input is a non-negative integer and within the array bounds.
    """
    if not isinstance(index_str, str):
        return False, "Input must be a string."

    if not re.match(r"^\d+$", index_str):  # Only digits allowed
        return False, "Input must be a non-negative integer."

    try:
        index = int(index_str)
    except ValueError:
        return False, "Input could not be converted to an integer."

    if index < 0:
        return False, "Index must be non-negative."

    if index >= array_length:
        return False, "Index is out of bounds."

    return True, index


def get_array_value(index_str, my_array):
    """
    Retrieves the value at the specified index in the array, after validation.
    """
    array_length = len(my_array)
    is_valid, validated_index = validate_index(index_str, array_length)

    if not is_valid:
        return f"Error: {validated_index}"  # Return the error message

    return my_array[validated_index]


# 2.  HTML Escaping (Output Encoding):
def escape_html(text):
    """
    Escapes HTML special characters to prevent XSS.
    """
    return html.escape(str(text))  # Ensure input is a string before escaping


# 3. Example Usage (Simulating Web Input):
def main():
    """
    Demonstrates how to use the function with input from the environment (simulating CGI).
    """
    # Simulate getting input from a web request (e.g., query string)
    # In a real web application, you'd use a framework like Flask or Django
    # to handle request parsing.
    
    # Get the index from the environment variable (simulating a GET request)
    index_str = os.environ.get("QUERY_STRING", "").split("=")[-1]  # Simple example, use proper parsing in real apps

    # Example array
    my_array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    # Get the value from the array
    result = get_array_value(index_str, my_array)

    # Escape the output before rendering it in HTML
    escaped_result = escape_html(result)

    # Print the escaped result (in a real web app, you'd return this as the response)
    print("Content-Type: text/html\n")  # HTTP header (for CGI)
    print(f"<html><body><h1>Value at index: {escaped_result}</h1></body></html>")


if __name__ == "__main__":
    main()

