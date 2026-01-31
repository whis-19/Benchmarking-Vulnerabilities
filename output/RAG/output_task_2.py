# This script provides a simplified illustration of automating a security check (e.g., static analysis)
# within a CI/CD pipeline.  In a real-world scenario, this would integrate with established CI/CD tools
# and invoke more comprehensive security tools.  The primary goal is to demonstrate the *concept* of
# automated security checks early in the development lifecycle.

import subprocess
import os

def run_static_analysis(source_code_path):
    """
    Simulates a static analysis tool.  In a real CI/CD pipeline, this would
    be replaced with an actual tool like Bandit, SonarQube, etc.

    Args:
        source_code_path: Path to the Python source code file.

    Returns:
        True if no issues found, False otherwise.
    """
    try:
        # In reality, this would run a static analysis tool
        # Example: subprocess.run(["bandit", "-r", source_code_path], capture_output=True, text=True, check=True)

        # Simulate a simplified check for hardcoded secrets
        with open(source_code_path, 'r') as f:
            code = f.read()
            if "password" in code.lower() or "api_key" in code.lower():
                print("Potential hardcoded secret found!")  # In reality log properly
                return False

        return True

    except subprocess.CalledProcessError as e:
        print(f"Static analysis failed: {e}")  # Log this properly
        return False


def main():
    """
    Demonstrates how to integrate a security check in a CI/CD workflow.
    """
    source_code_file = "example.py"  # Replace with the actual path to your code file

    # Create a dummy source code file for demonstration (in memory only)
    with open(source_code_file, 'w') as f:
        f.write("def my_function():\n")
        f.write("    password = 'P@$$wOrd'\n") # Simulate a hardcoded password.
        f.write("    print('Hello, world!')\n")

    # 1. Run static analysis
    analysis_result = run_static_analysis(source_code_file)

    # 2.  Based on the analysis, decide whether to proceed with the build/deployment.
    if analysis_result:
        print("Static analysis passed. Proceeding with the CI/CD pipeline.")
        # In a real pipeline, this would trigger subsequent steps like building, testing, and deployment.
    else:
        print("Static analysis failed. Aborting the CI/CD pipeline.")
        # This would typically halt the pipeline and notify the development team.

    # Clean up the dummy file
    os.remove(source_code_file)

if __name__ == "__main__":
    main()