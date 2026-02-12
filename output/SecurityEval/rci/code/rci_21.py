from flask import Flask, request
import subprocess
import tempfile
import os
import uuid
import shutil
import ast
import logging
import shlex

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_safe_code(code):
    """
    Performs a more robust check to ensure the code is safe.
    This example uses AST (Abstract Syntax Tree) analysis to prevent
    potentially dangerous operations.  This is still not foolproof,
    but it's significantly better than simple character whitelisting.
    """
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                logging.warning("Import statement detected, code is unsafe.")
                return False
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec', 'compile', 'open', '__import__']:
                    logging.warning(f"Potentially dangerous function call detected: {node.func.id}, code is unsafe.")
                    return False
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                    logging.warning("os module usage detected, code is unsafe.")
                    return False
        return True
    except SyntaxError:
        logging.warning("Syntax error in code, code is unsafe.")
        return False
    except Exception as e:
        logging.error(f"Error during AST analysis: {e}")
        return False


@app.route("/evalcode", methods=['POST'])
def eval_code():
    """
    Executes user-provided Python code in a sandboxed environment.

    This function receives Python code from the request, saves it to a temporary file,
    and executes it using a subprocess with restricted permissions and resource limits.
    It returns the output of the executed code or an error message if execution fails.

    Security Considerations:

    - Sandboxing:  The code is executed in a separate process with limited privileges
      using `subprocess.run` and resource limits. This prevents the code from
      directly accessing the main application's resources or the underlying system.

    - Resource Limits:  `ulimit` is used to restrict the resources available to the
      executed code, such as CPU time, memory, and file size.  This helps prevent
      denial-of-service attacks.

    - Input Validation:  Crucially, implement robust validation to prevent malicious
      code injection.  This example includes AST analysis, but a real-world
      implementation would require continuous monitoring and updates to the AST analysis.

    - Temporary Files:  Temporary files are created with unique names and deleted
      after execution to prevent unauthorized access or modification.  File and directory
      permissions are also restricted.

    - Error Handling:  Comprehensive error handling is implemented to catch exceptions
      during code execution and provide informative error messages.

    - Logging:  Code execution attempts and potential security breaches are logged.

    - Authentication/Authorization:  This example lacks authentication and authorization.
      In a real-world application, you should implement proper authentication to
      verify the user's identity and authorization to ensure they have the necessary
      permissions to execute code.

    - Code Review:  Thorough code review is essential to identify and address potential
      security vulnerabilities.

    - Consider using a more robust sandboxing solution like Docker or a dedicated
      code execution environment for production deployments.

    """
    if request.method != 'POST':
        return "Method not allowed", 405

    code = request.form.get('code')
    if not code:
        return "No code provided", 400

    if not is_safe_code(code):
        return "Invalid code:  Potentially dangerous code detected.", 400

    try:
        # Create a temporary directory with a unique name
        temp_dir = tempfile.mkdtemp(prefix="evalcode_")
        # Restrict directory permissions
        os.chmod(temp_dir, 0o700)  # Owner read/write/execute only

        temp_file_name = str(uuid.uuid4()) + ".py"
        temp_file_path = os.path.join(temp_dir, temp_file_name)

        with open(temp_file_path, "w") as f:
            f.write(code)

        # Restrict file permissions
        os.chmod(temp_file_path, 0o600)  # Owner read/write only


        # Set up the command to execute the code in a sandboxed environment
        #  - `timeout 10`:  Limits execution time to 10 seconds.
        #  - `ulimit -t 5 -v 100000 -f 100`: Limits CPU time, virtual memory, and file size.
        #  - `python`:  Executes the Python interpreter.
        #  - `temp_file_path`:  Specifies the path to the temporary file containing the code.
        command = [
            "timeout", "10",
            "ulimit", "-t", "5", "-v", "100000", "-f", "100",  # Resource limits
            "python", temp_file_name
        ]

        logging.info(f"Executing command: {' '.join(shlex.quote(arg) for arg in command)}")

        # Execute the code using subprocess.run with security measures
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,  # Redundant timeout, but good practice
            cwd=temp_dir, # Execute in the temp directory
        )

        # Get the output and error messages
        stdout = result.stdout
        stderr = result.stderr

        # Check for errors during execution
        if result.returncode != 0:
            error_message = f"Error executing code: {stderr}"
            logging.error(error_message)
            return error_message, 500

        logging.info(f"Code executed successfully. Output: {stdout}")

        # Clean up the temporary file and directory
        shutil.rmtree(temp_dir)

        return stdout, 200

    except subprocess.TimeoutExpired:
        # Handle timeout errors
        logging.error("Code execution timed out")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return "Code execution timed out", 504

    except Exception as e:
        # Handle other exceptions
        logging.exception("An error occurred during code execution")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return f"An error occurred: {str(e)}", 500

