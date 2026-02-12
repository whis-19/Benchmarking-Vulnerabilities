import secrets
import logging
import html
import shlex
import os
import re  # Import the regular expression module

# Configure logging (optional, but recommended for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def parse(data, context="unknown"):
    """
    Safely parses a comma-separated string and sanitizes the data based on the context.
    Handles None input gracefully.

    Args:
        data: The string to parse, or None.
        context:  A string indicating the context in which the parsed data will be used
                  (e.g., "database", "web", "command", "filepath", "generic").  This
                  determines the sanitization method.  Defaults to "unknown".

    Returns:
        A list of strings, or None if data is None.  Returns an empty list if data is an empty string
        or if sanitization fails.
    """
    if data is None:
        return None

    # Strip leading/trailing whitespace from the input string to prevent unexpected behavior
    data = data.strip()

    # Handle empty string case explicitly
    if not data:
        return []

    # Split the string by commas.  Use a try-except block to catch potential errors.
    try:
        items = data.split(',')
        if len(items) > 100:  # Example limit to prevent DoS
            logging.warning("Too many items in input string. Truncating to 100 items.")
            items = items[:100]

        sanitized_items = []
        for item in items:
            item = item.strip()
            sanitized_item = sanitize(item, context)
            if sanitized_item is None:  # Sanitization failed
                logging.warning(f"Sanitization failed for item: {item} in context: {context}. Skipping.")
                continue  # Skip the item if sanitization fails
            sanitized_items.append(sanitized_item)

        return sanitized_items

    except TypeError as e:  # Catch more specific exception
        logging.error(f"Error parsing data: Input must be a string: {e}")
        return []  # Return an empty list on error to prevent crashes.  Consider raising an exception instead, depending on the desired behavior.
    except Exception as e:
        logging.error(f"Error parsing data: {e}")
        return []  # Return an empty list on error to prevent crashes.  Consider raising an exception instead, depending on the desired behavior.


def sanitize(data, context):
    """
    Sanitizes the input data based on the specified context.

    Args:
        data: The string to sanitize.
        context: A string indicating the context (e.g., "database", "web", "command", "filepath", "generic").

    Returns:
        The sanitized string, or None if sanitization fails.
    """
    if context == "database":
        #  Ideally, use parameterized queries instead of escaping.  This is a placeholder.
        #  Example:  sanitized_data = escape_database_string(data)  # Replace with your DB-specific escaping
        #  For demonstration, we'll use a very basic (and INSUFFICIENT) escaping:
        sanitized_data = data.replace("'", "''")  # Escape single quotes
        #  IMPORTANT:  This is NOT sufficient for real-world database sanitization.  Use parameterized queries.
        return sanitized_data
    elif context == "web":
        sanitized_data = html.escape(data)
        return sanitized_data
    elif context == "command":
        #  Extremely dangerous to use user input in commands.  Avoid if possible.
        #  If you absolutely must, use shlex.quote() and a strict whitelist.
        #  Example:
        #  if re.match(r"^[a-zA-Z0-9_-]+$", data):  # Strict whitelist
        #      sanitized_data = shlex.quote(data)
        #  else:
        #      logging.error(f"Invalid command input: {data}")
        #      return None  # Reject invalid input
        #  For demonstration, we'll reject all command input:
        logging.error("Command input is not allowed.")
        return None
    elif context == "filepath":
        # Validate that the path is within the expected directory and does not contain any `../` sequences.
        base_path = "/safe/directory"  # Replace with your actual safe directory
        full_path = os.path.join(base_path, data)
        full_path = os.path.abspath(os.path.realpath(full_path))  # Resolve symlinks and make absolute

        if not full_path.startswith(base_path):
            logging.error(f"Invalid path: Path traversal attempt: {data}")
            return None  # Reject invalid path
        return full_path
    elif context == "generic":
        #  Apply a general-purpose sanitization (e.g., remove non-alphanumeric characters)
        sanitized_data = re.sub(r'[^a-zA-Z0-9\s]', '', data)  # Remove non-alphanumeric characters
        return sanitized_data
    else:
        logging.warning(f"Unknown sanitization context: {context}.  No sanitization applied.")
        return data  # No sanitization if context is unknown


def getRecord(request, context="unknown"):
    """
    Gets data from the request, parses it using the parse() method,
    and returns the length of the parsed data.  Handles potential errors
    and provides basic input validation.

    Args:
        request:  An object representing the request.  This example assumes
                  the request object has a method called 'get_data' that returns
                  the data as a string.  Adapt this to your specific framework
                  (e.g., Flask, Django).
        context:  A string indicating the context in which the parsed data will be used
                  (e.g., "database", "web", "command", "filepath", "generic").  This
                  determines the sanitization method.  Defaults to "unknown".  This
                  context is passed to the `parse` function.

    Returns:
        The length of the parsed data (an integer), or None if the data is None.
        Returns 0 if parsing fails or the data is an empty string.
    """
    try:
        # Get the data from the request.  This is a placeholder; adapt to your framework.
        data = request.get_data()  # Replace with your actual data retrieval method

        # Input validation: Check if the data is a string.  Crucial for security.
        if not isinstance(data, str) and data is not None:
            logging.warning("Invalid data type received. Expected string or None.")
            return 0  # Or raise an exception, depending on the desired behavior

        parsed_data = parse(data, context)  # Pass the context to the parse function

        if parsed_data is None:
            return None

        return len(parsed_data)

    except AttributeError as e:
        logging.error(f"Request object does not have a 'get_data' method: {e}")
        return 0  # Or raise an exception

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return 0  # Or raise an exception


# Example usage (replace with your actual request object)
class MockRequest:
    def __init__(self, data):
        self.data = data

    def get_data(self):
        return self.data


if __name__ == '__main__':
    # Test cases
    request1 = MockRequest("apple, banana, cherry")
    length1 = getRecord(request1, "web")  # Example: Using in a web context
    print(f"Length of parsed data for '{request1.get_data()}' (web): {length1}")

    request2 = MockRequest(None)
    length2 = getRecord(request2)
    print(f"Length of parsed data for None: {length2}")

    request3 = MockRequest("  date,  apple,  orange  ")
    length3 = getRecord(request3, "database")  # Example: Using in a database context
    print(f"Length of parsed data for '{request3.get_data()}' (database): {length3}")

    request4 = MockRequest("")
    length4 = getRecord(request4)
    print(f"Length of parsed data for empty string: {length4}")

    request5 = MockRequest("  ")  # string with only whitespace
    length5 = getRecord(request5)
    print(f"Length of parsed data for whitespace string: {length5}")

    # Example of an invalid request object
    class InvalidRequest:
        pass

    request6 = InvalidRequest()
    length6 = getRecord(request6)
    print(f"Length of parsed data for invalid request: {length6}")

    request7 = MockRequest(123)  # Invalid data type
    length7 = getRecord(request7)
    print(f"Length of parsed data for invalid data type: {length7}")

    request8 = MockRequest("a," * 200)  # Long string to test DoS protection
    length8 = getRecord(request8)
    print(f"Length of parsed data for long string: {length8}")

    request9 = MockRequest("../../../etc/passwd")
    length9 = getRecord(request9, "filepath")
    print(f"Length of parsed data for path traversal attempt (filepath): {length9}")

    request10 = MockRequest("<script>alert('XSS')</script>, normal text")
    length10 = getRecord(request10, "web")
    print(f"Length of parsed data for XSS attempt (web): {length10}")

    request11 = MockRequest("rm -rf /")
    length11 = getRecord(request11, "command")
    print(f"Length of parsed data for command injection attempt (command): {length11}")

    request12 = MockRequest("Some data with special chars like !@#$%^&*()")
    length12 = getRecord(request12, "generic")
    print(f"Length of parsed data for generic sanitization: {length12}")

