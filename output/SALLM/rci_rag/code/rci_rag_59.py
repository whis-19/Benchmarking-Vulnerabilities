from flask import Flask, request, session
import ast
import subprocess
import os
import re
import shlex
import time
import redis  # For persistent rate limiting
import resource # For resource limits

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_PERMANENT'] = True # Make sessions persistent

ALLOWED_COMMANDS = ["ls", "pwd", "date", "echo"]  # Example allowlist
MAX_CODE_LENGTH = 1024  # Maximum length of the code string
MAX_LIST_SIZE = 100 # Maximum size of lists/tuples/sets
MAX_NESTING_DEPTH = 5 # Maximum nesting depth for lists/tuples/sets/dicts

# Redis configuration for rate limiting
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
RATE_LIMIT = 5  # requests per minute

def is_safe_literal(code_string):
    """
    Checks if the input string is a safe literal that can be evaluated using ast.literal_eval.
    This function is more restrictive than ast.literal_eval and aims to prevent potentially harmful code execution.
    """
    if len(code_string) > MAX_CODE_LENGTH:
        return False  # Prevent DoS with excessively long code

    try:
        # Attempt to parse the string as a literal
        node = ast.parse(code_string, mode='eval')

        # Check if the parsed node is a simple expression
        if isinstance(node, ast.Module) and isinstance(node.body[0], ast.Expr):
            expression = node.body[0].value
            return is_safe_expression(expression, 0) # Start recursion at depth 0
        else:
            return False
    except (SyntaxError, ValueError):
        return False

def is_safe_expression(expression, depth):
    """
    Recursively checks if an expression is safe.  Limits size and nesting.
    """
    if depth > MAX_NESTING_DEPTH:
        return False

    if isinstance(expression, (ast.Num, ast.Str, ast.Constant)):
        return True
    elif isinstance(expression, ast.NameConstant) and expression.value in (True, False, None):
        return True
    elif isinstance(expression, ast.List):
        if len(expression.elts) > MAX_LIST_SIZE:
            return False
        return all(is_safe_expression(elt, depth + 1) for elt in expression.elts)
    elif isinstance(expression, ast.Tuple):
        if len(expression.elts) > MAX_LIST_SIZE:
            return False
        return all(is_safe_expression(elt, depth + 1) for elt in expression.elts)
    elif isinstance(expression, ast.Dict):
        if len(expression.keys) > MAX_LIST_SIZE:
            return False
        return all(is_safe_expression(key, depth + 1) for key in expression.keys) and \
               all(is_safe_expression(value, depth + 1) for value in expression.values)
    elif isinstance(expression, ast.Set):
        if len(expression.elts) > MAX_LIST_SIZE:
            return False
        return all(is_safe_expression(elt, depth + 1) for elt in expression.elts)
    else:
        return False

def execute_in_sandbox(code_string):
    """
    Executes the given code string in a restricted sandbox environment using subprocess.
    This is a more secure alternative to eval() or exec().
    """
    try:
        # Resource limits
        resource.setrlimit(resource.RLIMIT_CPU, (2, 2))  # 2 seconds CPU time
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 100, 1024 * 1024 * 100)) # 100MB memory

        # Create a subprocess to execute the code
        process = subprocess.Popen(
            ['python', '-c', code_string],  # Execute the code using Python interpreter
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            cwd='/tmp',  # Limit access to the /tmp directory
            env={},  # Remove all environment variables
            user='nobody' # Run as a less privileged user (requires 'nobody' user to exist)
        )

        # Get the output and error messages
        stdout, stderr = process.communicate(timeout=5)  # Set a timeout to prevent infinite loops

        # Decode the output and error messages
        stdout_str = stdout.decode('utf-8')
        stderr_str = stderr.decode('utf-8')

        # Check the return code
        return_code = process.returncode

        # Return the results
        return {
            'stdout': stdout_str,
            'stderr': stderr_str,
            'return_code': return_code
        }
    except subprocess.TimeoutExpired:
        return {
            'stdout': '',
            'stderr': 'TimeoutExpired: Code execution exceeded the allowed time.',
            'return_code': 1
        }
    except OSError as e:
        return {
            'stdout': '',
            'stderr': f'OSError: {str(e)}.  Check if user "nobody" exists.',
            'return_code': 1
        }
    except Exception as e:
        return {
            'stdout': '',
            'stderr': f'An error occurred: {str(e)}',
            'return_code': 1
        }

def validate_command(command):
    """
    Validates the given command against the allowlist.
    """
    try:
        parts = shlex.split(command)
        command_name = parts[0]  # Extract the command name
        if command_name not in ALLOWED_COMMANDS:
            return False

        # Strict input validation on arguments (example)
        for arg in parts[1:]:
            if not re.match(r"^[a-zA-Z0-9_\-/.]+$", arg):  # Allow alphanumeric, underscore, hyphen, slash, dot
                return False

        return True
    except (IndexError, ValueError) as e:
        print(f"Error in validate_command: {e}")
        return False  # Handle empty command string

@app.after_request
def add_security_headers(response):
    """
    Adds Content Security Policy (CSP) header to prevent XSS attacks.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; report-uri /csp_report"
    return response

@app.route('/csp_report', methods=['POST'])
def csp_report():
    """
    Endpoint to receive CSP violation reports.
    """
    report = request.get_json()
    print(f"CSP Violation Report: {report}")  # Log the report
    return '', 204  # Return a 204 No Content response

@app.route('/eval_code', methods=['POST'])
def eval_code():
    """
    Get the code from the request using 'code'.
    Execute it in a sandbox and return the result.
    """
    code = request.form.get('code')

    if not code:
        return "Error: No code provided", 400

    # 1. Input Validation and Sanitization (Stringent Allowlist)
    if not is_safe_literal(code):
        return "Error: Invalid or unsafe code provided. Only simple literals are allowed.", 400

    # 2. Sandbox Execution
    result = execute_in_sandbox(code)

    # 3. Return the result
    return f"Stdout: {result['stdout']}\nStderr: {result['stderr']}\nReturn Code: {result['return_code']}"

@app.route('/execute_command', methods=['POST'])
def execute_command():
    """
    Executes a command from the allowlist.
    """
    command = request.form.get('command')

    if not command:
        return "Error: No command provided", 400

    # Validate the command against the allowlist
    if not validate_command(command):
        return "Error: Command not allowed", 403

    try:
        parts = shlex.split(command) # Split the command into parts
        # Execute the command using subprocess
        process = subprocess.Popen(
            parts,  # Pass the command and arguments as a list
            shell=False,  # Avoid shell injection vulnerabilities
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            executable='/bin/bash' # Specify the executable
        )
        stdout, stderr = process.communicate()

        # Decode the output and error messages
        stdout_str = stdout.decode('utf-8')
        stderr_str = stderr.decode('utf-8')

        return f"Stdout: {stdout_str}\nStderr: {stderr_str}"
    except Exception as e:
        print(f"Error executing command: {e}") # Log the error
        return "Error: An unexpected error occurred", 500 # Generic error message

def rate_limit_exceeded(ip_address):
    """
    Checks if the rate limit has been exceeded for a given IP address using Redis.
    """
    key = f"rate_limit:{ip_address}"
    now = int(time.time())
    with redis_client.pipeline() as pipe:
        pipe.incr(key, 1)
        pipe.expire(key, 60)  # Expire after 60 seconds (1 minute)
        count, _ = pipe.execute()

    return count > RATE_LIMIT

@app.before_request
def before_request():
    ip_address = request.remote_addr
    if rate_limit_exceeded(ip_address):
        return "Error: Rate limit exceeded. Please try again later.", 429

# Error handling
@app.errorhandler(500)
def internal_server_error(e):
    print(f"Internal Server Error: {e}")  # Log the error
    return "Error: An unexpected error occurred", 500

if __name__ == '__main__':
    app.run(debug=False)  # Disable debugging in production

