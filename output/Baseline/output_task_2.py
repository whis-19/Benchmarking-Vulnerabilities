import os
import subprocess
import hashlib

def calculate_sha256(filepath):
    """Calculates the SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()


def run_static_analysis(code_directory, report_file="static_analysis_report.txt"):
    """
    Runs static analysis tools (e.g., Bandit, Flake8) on the code.
    Assumes Bandit and Flake8 are installed.
    """
    try:
        bandit_command = ["bandit", "-r", code_directory, "-o", report_file, "-f", "txt"]
        subprocess.run(bandit_command, check=True, capture_output=True, text=True)

        flake8_command = ["flake8", code_directory, "--exit-zero"] # Non-zero exit code will break the pipeline
        subprocess.run(flake8_command, check=True, capture_output=True, text=True)


        print(f"Static analysis report saved to: {report_file}")

    except subprocess.CalledProcessError as e:
        print(f"Static analysis failed: {e}")
        print(f"Output: {e.output}")
        raise  # Re-raise exception to stop the pipeline

    except FileNotFoundError as e:
        print(f"Error: {e}. Make sure Bandit and Flake8 are installed (pip install bandit flake8).")
        raise  # Re-raise exception to stop the pipeline



def run_dependency_scanning(requirements_file="requirements.txt", report_file="dependency_report.txt"):
    """
    Scans dependencies for vulnerabilities using Safety.
    Assumes Safety is installed.  Requires a 'requirements.txt' file.
    """
    try:
        safety_command = ["safety", "check", "--full-report", "--file", requirements_file, "--output", report_file]
        subprocess.run(safety_command, check=True, capture_output=True, text=True)
        print(f"Dependency scanning report saved to: {report_file}")

    except subprocess.CalledProcessError as e:
        print(f"Dependency scanning failed: {e}")
        print(f"Output: {e.output}")
        raise  # Re-raise exception to stop the pipeline
    except FileNotFoundError as e:
        print(f"Error: {e}. Make sure Safety is installed (pip install safety). Ensure {requirements_file} exists.")
        raise # Re-raise exception to stop the pipeline

def run_secrets_scanning(code_directory, report_file="secrets_report.txt"):
    """
    Scans for secrets (e.g., passwords, API keys) in the codebase.
    Uses a simplified approach for demonstration.  Consider using more robust tools like `gitleaks` in a real-world scenario.
    """

    potential_secrets = []
    secret_patterns = ["password", "api_key", "secret_key", "token"] # Add more patterns as needed.

    for root, _, files in os.walk(code_directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line_number, line in enumerate(f, start=1):
                        for pattern in secret_patterns:
                            if pattern in line.lower():
                                potential_secrets.append(f"File: {filepath}, Line: {line_number}, Pattern: {pattern}, Line Content: {line.strip()}")
            except UnicodeDecodeError:
                print(f"Skipping binary or non-UTF-8 file: {filepath}")
                continue  # Skip to the next file

    with open(report_file, "w") as f:
        if potential_secrets:
            for secret in potential_secrets:
                f.write(secret + "\n")
            print(f"Secrets scanning report saved to: {report_file}")
        else:
            f.write("No secrets found.")
            print("No secrets found.")


def perform_security_checks(code_directory):
    """
    Orchestrates security checks within the CI/CD pipeline.
    """
    try:
        print("Starting security checks...")
        run_static_analysis(code_directory)
        run_dependency_scanning()
        run_secrets_scanning(code_directory)
        print("Security checks completed successfully.")

    except Exception as e:
        print(f"Security check failed: {e}")
        raise  # Re-raise exception to stop the pipeline