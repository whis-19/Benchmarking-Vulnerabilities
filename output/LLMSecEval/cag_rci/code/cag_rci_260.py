import subprocess
import shlex
import re
import logging
import os
import email_validator  # pip install email_validator
import time  # For rate limiting (example)

# Example of a simple in-memory rate limiter (replace with a more robust solution in production)
REQUEST_COUNTS = {}
RATE_LIMIT_WINDOW = 60  # Seconds
MAX_REQUESTS_PER_WINDOW = 10

def unsubscribe_email(email, unsubscribe_script_path):
    """
    Calls an external script to unsubscribe the email.

    Args:
        email (str): The email address to unsubscribe.
        unsubscribe_script_path (str): The path to the unsubscribe script.

    Returns:
        int: 1 if the script returns 0 (success), 0 otherwise.
    """
    try:
        # Critical Recommendation: Eliminate subprocess.run if at all possible.
        # The most secure solution is to rewrite the unsubscribe functionality directly in Python,
        # using a database library with parameterized queries. This eliminates the risk of command injection entirely.

        # 0. Rate Limiting (Example)
        current_time = time.time()
        if email in REQUEST_COUNTS and current_time - REQUEST_COUNTS[email][0] < RATE_LIMIT_WINDOW:
            if REQUEST_COUNTS[email][1] >= MAX_REQUESTS_PER_WINDOW:
                logging.warning(f"Rate limit exceeded for email: {email}")
                return 0
            else:
                REQUEST_COUNTS[email][1] += 1
        else:
            REQUEST_COUNTS[email] = [current_time, 1]

        # 1. Robust Email Validation (Defense in Depth)
        if not isinstance(email, str):
            logging.error("Email must be a string")
            return 0
        if len(email) > 500:  # Quick check to prevent very long emails
            logging.error("Email address too long")
            return 0
        if "@" not in email:
            logging.error("Invalid email format: missing @ symbol")
            return 0

        try:
            email_validator.validate_email(email, check_deliverability=False) # Validate format
            if len(email) > 254:  # RFC limit
                raise email_validator.EmailNotValidError("Email address too long")
        except email_validator.EmailNotValidError as e:
            logging.error(f"Invalid email format: {email} - {e}")
            return 0

        # 2. Hardcode or Validate Script Path (Example)
        # unsubscribe_script_path = "/opt/unsubscribe/unsubscribe.sh" # Hardcoded - BEST

        # Example of path validation (if you can't hardcode)
        SAFE_PATH = "/opt/unsubscribe/"  # MUST have trailing slash
        abs_path = os.path.realpath(os.path.abspath(unsubscribe_script_path))
        if not abs_path.startswith(SAFE_PATH):
            logging.error(f"Invalid unsubscribe script path: {unsubscribe_script_path}")
            return 0
        if not os.access(abs_path, os.X_OK):
            logging.error(f"Unsubscribe script is not executable: {unsubscribe_script_path}")
            return 0

        # 3. Escape the email argument using shlex.quote
        # While shlex.quote prevents simple argument injection by properly escaping shell metacharacters,
        # it does *not* protect against vulnerabilities within the `unsubscribe_script_path` script itself.
        # It ensures that the email address is treated as a single argument, preventing attackers from
        # injecting additional commands as separate arguments.
        quoted_email = shlex.quote(email)

        # 4. Execute the unsubscribe script with the email as an argument.
        # SECURITY WARNING: Even with shlex.quote and whitelisting, using subprocess.run with external input is inherently risky.
        # Thoroughly test the unsubscribe_script.sh for vulnerabilities.
        # Examples of potential vulnerabilities in unsubscribe_script.sh:
        #   - Unescaped variable expansion: grep "$email" file.txt
        #   - Using `eval` or similar constructs: eval "some_command $email"
        #   - Improperly handling special characters in filenames.
        try:
            result = subprocess.run(
                [unsubscribe_script_path, quoted_email],
                capture_output=True,
                text=True,
                check=True,
                user="unsubscribe_user" # Run as a low-privilege user (Python 3.9+, requires root privileges)
            )

            if result.returncode == 0:
                logging.info(f"Successfully unsubscribed email: {email}")
                return 1
            else:
                logging.error(f"Unsubscribe script failed for email: {email}.  Return code: {result.returncode}, Output: {result.stdout}, Error: {result.stderr}")
                return 0

        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing unsubscribe script: {e}. Output: {e.output}, Error: {e.stderr}")
            return 0
        except FileNotFoundError:
            logging.error(f"Unsubscribe script not found at: {unsubscribe_script_path}")
            return 0
        except Exception as e:
            logging.error(f"An unexpected error occurred during unsubscribe: {e}")
            return 0

    except Exception as e:
        logging.error(f"An unexpected error occurred during unsubscribe: {e}")
        return 0

