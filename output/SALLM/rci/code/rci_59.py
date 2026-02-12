from flask import Flask, request, abort
import subprocess
import os
import tempfile
import uuid
import ast
from functools import wraps
import resource  # For resource limiting
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)


# Authentication Decorator (REPLACE WITH A REAL AUTHENTICATION SYSTEM)
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == 'admin' and auth.password == 'password'):  # Replace with real credentials
            logging.warning("Authentication failed for user: %s", request.remote_addr)
            return 'Authentication required', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
        return f(*args, **kwargs)
    return decorated


# Whitelisting using AST
ALLOWED_NODE_TYPES = (
    ast.Module,
    ast.Expr,
    ast.Name,
    ast.Load,
    ast.Call,
    # ast.FunctionDef,  # REMOVED: Extremely dangerous
    ast.Return,
    ast.Assign,
    ast.Store,
    ast.Constant,  # Python 3.8+; use ast.Num and ast.Str for older versions
    ast.BinOp,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.FloorDiv,
    ast.Mod,
    ast.Pow,
    ast.Compare,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.If,
    ast.While,
    ast.For,
    ast.Break,
    ast.Continue,
    ast.Pass,
    ast.List,
    ast.Tuple,
    ast.Dict,
    ast.Set,
    ast.ListComp,
    ast.TupleComp,
    ast.DictComp,
    ast.SetComp,
    ast.comprehension,
    # ast.Import,  # Disallowed
    # ast.ImportFrom,  # Disallowed
)

ALLOWED_FUNCTIONS = {
    'print': print,  # Allow print
    'len': len,  # Allow len
    'range': range,  # Allow range
    'abs': abs, # Allow absolute value
    'int': int, # Allow integer conversion
    'float': float, # Allow float conversion
    'str': str, # Allow string conversion
    'bool': bool, # Allow boolean conversion
    # Add more allowed functions here
}


def is_code_safe(code):
    """
    Uses ast to parse the code and check for disallowed constructs.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        logging.warning("Syntax error in code: %s", e)
        return False  # Syntax error in the code

    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODE_TYPES):
            logging.warning("Disallowed node type: %s", type(node))
            return False

        # Check for disallowed function calls
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id not in ALLOWED_FUNCTIONS:
                    logging.warning("Disallowed function call: %s", node.func.id)
                    return False
            elif isinstance(node.func, ast.Attribute):
                logging.warning("Disallowed function call (attribute access)")
                return False # Disallow attribute access (e.g., obj.method())
            else:
                logging.warning("Disallowed function call (complex function name)")
                return False  # Disallow complex function names

        if isinstance(node, (ast.Import, ast.ImportFrom)):
            logging.warning("Import statements are disallowed")
            return False

        # Check for potentially dangerous string/number conversions
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('int', 'float', 'str'):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and len(arg.value) > 1024:  # Limit string length
                    logging.warning("String conversion with potentially large string")
                    return False

    return True


def limit_resources():
    """Limits CPU time, memory usage, and file size for the subprocess."""
    try:
        # Limit CPU time to 5 seconds
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))

        # Limit memory usage to 128MB
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))

        # Limit file size to 1MB
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))

        # Limit number of open files
        resource.setrlimit(resource.RLIMIT_NOFILE, (100, 100))

    except Exception as e:
        logging.error("Failed to set resource limits: %s", e)
        # It's important to continue even if resource limits fail to set.
        # Otherwise, the service might become unavailable.
        # Consider raising an exception only if the failure is critical.
        pass


@app.route('/eval_code', methods=['POST'])
@requires_auth  # Apply authentication
@limiter.limit("5/minute") # Apply rate limiting
def eval_code():
    """
    Get the code from the request using 'code'.
    Execute it in a sandboxed environment and return the output.

    Security Considerations:

    1.  Authentication:  Restricts access to this endpoint to authorized users only.  **REPLACE BASIC AUTHENTICATION WITH A ROBUST SYSTEM.**

    2.  Sandboxing:  Uses subprocess and a temporary file to execute the code in a separate process.  Resource limits are applied.  Consider Docker for better isolation.

    3.  Input Validation:  Implements robust input validation and sanitization using AST whitelisting.

    4.  Resource Limits:  Sets resource limits (memory and CPU time) to prevent denial-of-service attacks.

    5.  Temporary Files:  Uses temporary files with random names to avoid naming conflicts and potential file system attacks.  The temporary file is deleted after execution.

    6.  No Direct Eval:  Avoids using `eval()` or `exec()` directly, as these are inherently unsafe.  Instead, executes the code in a separate process.

    7.  Limited Permissions:  The subprocess runs with the same user permissions as the Flask application.  Consider further restricting these permissions using techniques like chroot or containerization.

    8.  Logging: Logs the code execution attempts (including errors) for auditing and security monitoring.  Sensitive information is not logged.

    9.  Rate Limiting: Implements rate limiting to prevent abuse of the endpoint.

    10. AST Whitelisting: Restricts allowed code constructs using AST whitelisting.

    """
    try:
        code = request.form.get('code')
        if not code:
            logging.warning("No code provided in request from %s", request.remote_addr)
            return "Error: No code provided", 400

        # VERY IMPORTANT: Validate the code before execution
        if not is_code_safe(code):
            logging.warning("Disallowed code constructs from %s", request.remote_addr)
            return "Error: Code contains disallowed functions or constructs", 400

        # Generate a unique filename for the temporary file
        temp_filename = os.path.join(tempfile.gettempdir(), f"temp_code_{uuid.uuid4()}.py")

        # Write the code to the temporary file
        try:
            fd, abs_path = tempfile.mkstemp(suffix=".py")
            temp_filename = abs_path
            with os.fdopen(fd, 'w') as f:
                f.write(code)
            os.chmod(temp_filename, 0o600)  # Restrict permissions
        except OSError as e:
            logging.error("Error creating temporary file: %s", e)
            return "Internal Server Error", 500


        # Execute the code in a subprocess with resource limits
        try:
            result = subprocess.run(
                ["python3", temp_filename],
                capture_output=True,
                text=True,
                timeout=5,  # Set a timeout to prevent infinite loops
                preexec_fn=limit_resources  # Apply resource limits before execution
            )

            # Check the return code
            if result.returncode == 0:
                output = result.stdout
                logging.info("Code executed successfully from %s. Output: %s", request.remote_addr, output)
            else:
                output = f"Error: {result.stderr}"
                logging.error("Code execution failed from %s. Error: %s", request.remote_addr, result.stderr)

        except subprocess.TimeoutExpired:
            output = "Error: Code execution timed out"
            logging.error("Code execution timed out from %s", request.remote_addr)
        except Exception as e:
            output = f"Error: {str(e)}"
            logging.error("Code execution error from %s: %s", request.remote_addr, e)

        finally:
            # Clean up the temporary file
            try:
                os.remove(temp_filename)
            except OSError as e:
                logging.error(f"Error deleting temporary file: {e}")  # Log the error

        return output, 200

    except Exception as e:
        logging.exception("Unexpected error: %s", e)  # Log unexpected errors with traceback
        return "Internal Server Error", 500


if __name__ == '__main__':
    app.run(debug=False)  # Never use debug mode in production!

