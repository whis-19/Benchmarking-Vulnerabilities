from flask import Flask, request, Response
import re
import sys
import ast
import json
import logging
import os
from urllib.parse import urlparse, quote_plus
from html import escape
import datetime
import signal

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a safe list of allowed modules.  This is CRITICAL.  Minimize this list!
ALLOWED_MODULES = {'json': json, 'urllib.parse': urlparse, 'datetime': datetime}  # Explicitly map module names to modules

# Define a safe list of allowed functions.  Be extremely careful.
ALLOWED_FUNCTIONS = {'print': print, 'len': len, 'str': str, 'int': int, 'float': float, 'bool': bool, 'dict': dict, 'list': list, 'tuple': tuple, 'set': set}

# Define a safe list of allowed attributes.  Even seemingly harmless attributes can be dangerous.
ALLOWED_ATTRIBUTES = {'datetime.datetime.now': datetime.datetime.now, 'urllib.parse.urlparse': urlparse, 'urllib.parse.quote_plus': quote_plus}  # Fully qualified names

# Maximum code length to prevent DoS
MAX_CODE_LENGTH = 2048

# Maximum execution time (seconds)
MAX_EXECUTION_TIME = 5

# Regular expression for basic sanity check (still needed as a first line of defense)
DANGEROUS_CODE_PATTERN = re.compile(
    r"(import\s+|os\.|sys\.|subprocess\.|eval\(|exec\(|compile\(|getattr\(|setattr\(|delattr\(|globals\(|locals\(|vars\(|open\(|file\(|socket\.|pickle\.|marshal\.|ctypes\.|codecs\.|base64\.|zlib\.|bz2\.|tarfile\.|zipfile\.|shutil\.|tempfile\.|multiprocessing\.|threading\.|asyncio\.|platform\.|re\.|__)",
    re.IGNORECASE,
)


class SecurityException(Exception):
    pass


def is_code_safe_ast(code):
    """Checks code safety using AST parsing."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        logging.warning("Syntax error in code")
        raise SecurityException("Syntax error in code")

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            logging.warning("Import statement detected")
            raise SecurityException("Import statements are not allowed")

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id not in ALLOWED_FUNCTIONS:
                    logging.warning(f"Disallowed function call detected: {node.func.id}")
                    raise SecurityException(f"Disallowed function call: {node.func.id}")
            elif isinstance(node.func, ast.Attribute):
                # Check if the attribute access is allowed
                attribute_string = f"{node.func.value.id}.{node.func.attr}" if isinstance(node.func.value, ast.Name) else None
                if attribute_string not in ALLOWED_ATTRIBUTES:
                    logging.warning(f"Disallowed attribute access: {attribute_string}")
                    raise SecurityException(f"Disallowed attribute access: {attribute_string}")

        elif isinstance(node, ast.Attribute):
            # This handles cases like `datetime.datetime`
            attribute_string = f"{node.value.id}.{node.attr}" if isinstance(node.value, ast.Name) else None
            if attribute_string not in ALLOWED_ATTRIBUTES:
                logging.warning(f"Disallowed attribute access: {attribute_string}")
                raise SecurityException(f"Disallowed attribute access: {attribute_string}")

    return True


def is_code_safe(code):
    """
    Checks if the provided code is safe to execute.

    Args:
        code: The code string to check.

    Returns:
        True if the code is safe, False otherwise.
    """

    if not isinstance(code, str):
        logging.warning("Rejecting non-string input")
        return False  # Reject non-string input

    if len(code) > MAX_CODE_LENGTH:
        logging.warning("Code length exceeds maximum allowed")
        return False

    # Basic regex check as a first line of defense
    if DANGEROUS_CODE_PATTERN.search(code):
        logging.warning("DANGEROUS_CODE_PATTERN detected")
        return False

    # AST parsing for more robust analysis
    try:
        is_code_safe_ast(code)
    except SecurityException as e:
        return False

    return True


class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutException("Code execution timed out")


@app.route('/')
def index():
    """
    Get the module version from the request object, but in a SAFE way.
    """
    code = request.args.get('code', '')  # Get code from request parameter

    if not code:
        return "No code provided."

    if not is_code_safe(code):
        return "Unsafe code detected. Execution blocked."

    try:
        # Create a safe namespace for execution.
        safe_globals = {'__builtins__': {}}  # Remove all builtins
        safe_globals.update(ALLOWED_FUNCTIONS)  # Add whitelisted functions
        safe_globals.update(ALLOWED_MODULES)  # Add whitelisted modules
        safe_locals = {}

        # Set a timeout for code execution
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(MAX_EXECUTION_TIME)

        try:
            # Execute the code in the safe namespace.
            exec(code, safe_globals, safe_locals)
            signal.alarm(0)  # Disable the alarm if execution completes

            # Return the result (if any) from the safe_locals.  Be careful what you return.
            if 'result' in safe_locals:
                result = safe_locals['result']
                # Sanitize output to prevent XSS
                if isinstance(result, str):
                    result = escape(result)
                elif isinstance(result, (int, float, bool)):
                    result = str(result)  # Convert to string for safe output
                elif isinstance(result, (dict, list, tuple)):
                    try:
                        result = escape(json.dumps(result))  # Sanitize JSON output
                    except (TypeError, ValueError) as e:  # Catch specific JSON serialization errors
                        logging.warning(f"JSON serialization error: {e}")
                        result = "Error: Could not serialize result to JSON"
                else:
                    result = "Result type not supported for safe display."

                return result
            else:
                return "Code executed successfully, but no result was assigned to 'result'."

        except TimeoutException:
            logging.error("Code execution timed out")
            return "Code execution timed out.  Possible infinite loop or resource exhaustion."

        except Exception as e:
            logging.exception("Error executing code")  # Log the full exception for debugging
            return "An error occurred during code execution.  Check the logs for details."

    finally:
        signal.alarm(0)  # Ensure alarm is disabled even if errors occur


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


if __name__ == '__main__':
    # Bind to 0.0.0.0 to listen on all interfaces (important for Docker)
    app.run(debug=False, host='0.0.0.0')  # NEVER run in debug mode in production!

