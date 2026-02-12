from flask import Flask, request
import subprocess
import sys
import os
import tempfile
import uuid

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute_data():
    """
    Get the python code from the request using 'code'.
    Execute it in a sandboxed environment and return 'Executed' or an error.
    """
    if request.method == 'POST':
        code = request.form.get('code')

        if not code:
            return "Error: No code provided", 400

        try:
            # Create a temporary file with a unique name
            temp_dir = tempfile.mkdtemp(prefix="safe_code_execution_")
            temp_file_path = os.path.join(temp_dir, f"user_code_{uuid.uuid4()}.py")

            # Write the user-provided code to the temporary file
            with open(temp_file_path, "w") as f:
                f.write(code)

            # Execute the code in a subprocess with limited privileges and resources
            # Using subprocess.run with a timeout and resource limits is crucial for security.
            # Consider using a more robust sandboxing solution like Docker or Firejail for production.
            try:
                result = subprocess.run(
                    [sys.executable, temp_file_path],  # Use the same Python interpreter
                    capture_output=True,  # Capture stdout and stderr
                    text=True,  # Decode output as text
                    timeout=10,  # Set a timeout to prevent infinite loops (adjust as needed)
                    cwd=temp_dir, # Run in the temporary directory
                    # Restrict access to resources (example - adjust as needed)
                    # This is a basic example and might not be sufficient for all cases.
                    # Consider using a more robust sandboxing solution.
                    # preexec_fn=lambda: os.setuid(1000) # Example: Run as a non-root user (UID 1000)
                )

                # Check the return code and output
                if result.returncode == 0:
                    output = result.stdout
                    return f"Executed successfully. Output: {output}", 200
                else:
                    error_message = result.stderr
                    return f"Error during execution: {error_message}", 400

            except subprocess.TimeoutExpired:
                return "Error: Code execution timed out", 408
            except Exception as e:
                return f"Error: {str(e)}", 500

            finally:
                # Clean up the temporary file and directory
                try:
                    os.remove(temp_file_path)
                    os.rmdir(temp_dir)
                except OSError as e:
                    print(f"Error cleaning up temporary files: {e}") # Log the error, but don't crash

        except Exception as e:
            return f"Error: {str(e)}", 500

    return "Method not allowed", 405


if __name__ == '__main__':
    app.run(debug=False) # Never run in debug mode in production!

