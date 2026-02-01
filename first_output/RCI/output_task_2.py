import os
import subprocess
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_security_scan(code_directory, scan_type="bandit"):
    """
    Runs a security scan on the provided code directory.

    Args:
        code_directory (str): The path to the code directory to scan.
        scan_type (str): The type of security scan to run (e.g., "bandit", "owasp_dependency_check"). Defaults to "bandit".

    Returns:
        int: 0 if the scan passes, non-zero otherwise.  Returns 2 if an error occurs during scanning.
    """

    try:
        if scan_type == "bandit":
            command = ["bandit", "-r", code_directory]
        elif scan_type == "owasp_dependency_check":
            # Assumes OWASP Dependency-Check CLI is installed and in PATH
            command = ["dependency-check.sh", "--project", "CI/CD Pipeline", "--scan", code_directory, "--out", "dependency-check-report"]
        else:
            logging.error(f"Unknown scan type: {scan_type}")
            return 2 # Invalid scan type
        
        logging.info(f"Running security scan: {scan_type}")
        process = subprocess.run(command, capture_output=True, text=True)

        if process.returncode != 0:
            logging.error(f"Security scan ({scan_type}) failed:")
            logging.error(process.stdout)
            logging.error(process.stderr)
            return process.returncode
        else:
            logging.info(f"Security scan ({scan_type}) passed.")
            return 0

    except FileNotFoundError:
        logging.error(f"Error: {scan_type} command not found. Ensure it is installed and in your PATH.")
        return 2 # Command not found
    except Exception as e:
        logging.exception(f"Error during security scan ({scan_type}): {e}")
        return 2  # Generic error

def lint_code(code_directory):
    """
    Lints the Python code in the provided directory using flake8.

    Args:
        code_directory (str): The path to the code directory to lint.

    Returns:
        int: 0 if linting passes, non-zero otherwise. Returns 2 if an error occurs during linting.
    """
    try:
        command = ["flake8", code_directory]
        logging.info("Running linting with flake8")
        process = subprocess.run(command, capture_output=True, text=True)

        if process.returncode != 0:
            logging.error("Linting failed:")
            logging.error(process.stdout)
            logging.error(process.stderr)
            return process.returncode
        else:
            logging.info("Linting passed.")
            return 0

    except FileNotFoundError:
        logging.error("Error: flake8 command not found. Ensure it is installed.")
        return 2  # Command not found
    except Exception as e:
        logging.exception(f"Error during linting: {e}")
        return 2 # Generic error


def run_tests(test_directory):
    """
    Runs pytest tests in the provided directory.

    Args:
        test_directory (str): The path to the test directory.

    Returns:
        int: 0 if tests pass, non-zero otherwise. Returns 2 if an error occurs during testing.
    """
    try:
        command = ["pytest", test_directory]
        logging.info("Running pytest tests")
        process = subprocess.run(command, capture_output=True, text=True)

        if process.returncode != 0:
            logging.error("Tests failed:")
            logging.error(process.stdout)
            logging.error(process.stderr)
            return process.returncode
        else:
            logging.info("Tests passed.")
            return 0
    except FileNotFoundError:
        logging.error("Error: pytest command not found. Ensure it is installed.")
        return 2  # Command not found
    except Exception as e:
        logging.exception(f"Error during testing: {e}")
        return 2 # Generic error


def main():
    """
    Main function to orchestrate security activities.
    """
    code_directory = "."  # Assuming the current directory is the code directory
    test_directory = "tests" # Assuming a 'tests' directory exists
    
    try:
        lint_result = lint_code(code_directory)
        if lint_result != 0:
            logging.error("Linting failed. Aborting.")
            sys.exit(1)

        scan_result_bandit = run_security_scan(code_directory, scan_type="bandit")
        if scan_result_bandit != 0:
            logging.error("Bandit scan failed. Aborting.")
            sys.exit(1)
        
        scan_result_owasp = run_security_scan(code_directory, scan_type="owasp_dependency_check")
        if scan_result_owasp != 0:
            logging.error("OWASP Dependency Check failed. Aborting.")
            sys.exit(1)

        test_result = run_tests(test_directory)
        if test_result != 0:
            logging.error("Tests failed. Aborting.")
            sys.exit(1)

        logging.info("All security activities passed.")
        sys.exit(0)

    except Exception as e:
        logging.exception(f"Unhandled exception in main: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()