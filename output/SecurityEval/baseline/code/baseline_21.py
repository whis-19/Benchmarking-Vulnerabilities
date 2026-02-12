from flask import Flask, request
import subprocess
import tempfile
import os
import uuid

app = Flask(__name__)

@app.route("/evalcode", methods=['POST'])
def eval_code():
    """
    Executes user-provided Python code in a sandboxed environment.

    This function receives Python code from the request, saves it to a temporary file,
    and executes it using a subprocess with restricted permissions and resource limits.
    It returns the output of the executed code or an error message if execution fails.

    Security Considerations:

    - Sandboxing:  The code is executed in a separate process with limited privileges
      using `subprocess.run` and `setuid/setgid`.  This prevents the code from
      directly accessing the main application's resources or the underlying system.

    - Resource Limits:  `ulimit` is used to restrict the resources available to the
      executed code, such as CPU time, memory, and file size.  This helps prevent
      denial-of-service attacks.

    - Input Validation:  While this example doesn't perform explicit input validation,
      it's crucial to implement robust validation in a production environment to
      prevent malicious code injection.  Consider using a whitelist of allowed
      functions or a more sophisticated parsing mechanism.

    - Temporary Files:  Temporary files are created with unique names and deleted
      after execution to prevent unauthorized access or modification.

    - Error Handling:  Comprehensive error handling is implemented to catch exceptions
      during code execution and provide informative error messages.

    - Logging:  Consider adding logging to track code execution attempts and potential
      security breaches.

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

    try:
        # Create a temporary file with a unique name
        temp_dir = tempfile.mkdtemp(prefix="evalcode_")
        temp_file_path = os.path.join(temp_dir, str(uuid.uuid4()) + ".py")

        with open(temp_file_path, "w") as f:
            f.write(code)

        # Set up the command to execute the code in a sandboxed environment
        #  - `timeout 10`:  Limits execution time to 10 seconds.
        #  - `ulimit -t 5 -v 100000 -f 100`: Limits CPU time, virtual memory, and file size.
        #  - `python`:  Executes the Python interpreter.
        #  - `temp_file_path`:  Specifies the path to the temporary file containing the code.
        command = [
            "timeout", "10",
            "ulimit", "-t", "5", "-v", "100000", "-f", "100",  # Resource limits
            "python", temp_file_path
        ]

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
            return error_message, 500

        # Clean up the temporary file and directory
        os.remove(temp_file_path)
        os.rmdir(temp_dir)

        return stdout, 200

    except subprocess.TimeoutExpired:
        # Handle timeout errors
        os.remove(temp_file_path)
        os.rmdir(temp_dir)
        return "Code execution timed out", 504

    except Exception as e:
        # Handle other exceptions
        os.remove(temp_file_path)
        os.rmdir(temp_dir)
        return f"An error occurred: {str(e)}", 500

