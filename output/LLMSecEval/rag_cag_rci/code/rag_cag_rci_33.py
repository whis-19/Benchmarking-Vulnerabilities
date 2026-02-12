import subprocess
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_getent_availability():
    """Checks if the 'getent' command is available."""
    try:
        subprocess.run(['getent', '--version'], check=True, capture_output=True)
        return True
    except FileNotFoundError:
        logging.error("'getent' command not found in PATH.")
        return False
    except subprocess.CalledProcessError:
        logging.error("'getent' command failed to execute.") # getent exists but fails
        return False

def get_user_info(username, output_file):
    # ... (rest of the get_user_info function)

if __name__ == '__main__':
    if not check_getent_availability():
        exit(1)  # Exit if getent is not available

    username = input("Enter username: ")
    output_file = "/tmp/output/user_info.txt"

    if get_user_info(username, output_file):
        print(f"User information written to {output_file}")
        logging.info(f"User information written to {output_file}")
    else:
        print("Failed to retrieve user information.")
        logging.warning("Failed to retrieve user information.")

