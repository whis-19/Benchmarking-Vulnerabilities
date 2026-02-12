import os
import re
import json
import logging
import base64
import hashlib
import time  # Import the time module

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration file path (store outside web root!)
CONFIG_FILE = "config.json"

# --- Environment Variables Example ---
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
if DATABASE_PASSWORD is None:
    logging.critical("DATABASE_PASSWORD environment variable not set! Exiting.")
    exit(1)  # Or raise an exception

def load_config():
    """Loads configuration from the config file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
        password_regex = config.get("password_regex", r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$")

        # Validate the regex (example: limit length and complexity)
        if len(password_regex) > 100:  # Arbitrary limit
            logging.warning("Password regex too long, using default.")
            config["password_regex"] = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$"
        # Add more checks here to prevent overly permissive regexes

    except FileNotFoundError:
        # Handle first-time setup or missing config file
        logging.warning("Configuration file not found. Running first-time setup.")
        print("Configuration file not found.  Running first-time setup.")
        return {}  # Return an empty dictionary for initial setup
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON in config file: {e}")
        print("Error reading configuration file. Check the file format.")
        return {} # Return empty dict to prevent further errors
    return config

def save_config(config):
    """Saves configuration to the config file."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        # Restrict access to the configuration file (OS-dependent)
        os.chmod(CONFIG_FILE, 0o600)  # Read/write for owner only
    except Exception as e:
        logging.error(f"Error saving configuration: {e}")
        print("Error saving configuration. Check file permissions.")

def check_mod(username, password):
    config = load_config()
    if "users" not in config or username not in config["users"]:
        return "false"

    user_data = config["users"][username]
    if "failed_attempts" in user_data and user_data["failed_attempts"] >= 3:  # Example: Lock after 3 attempts
        if "lockout_time" in user_data and time.time() < user_data["lockout_time"]:
            return "account_locked"  # Or a more informative message
        else:
            # Lockout time has expired, reset failed attempts
            user_data["failed_attempts"] = 0
            user_data.pop("lockout_time", None) # Remove lockout time if it exists
            save_config(config)

    if verify_password(username, password):
        # Reset failed attempts on successful login
        user_data["failed_attempts"] = 0
        user_data.pop("lockout_time", None) # Remove lockout time if it exists
        save_config(config)
        return "true"
    else:
        logging.warning(f"Failed login attempt for user: {username}")
        if "failed_attempts" not in user_data:
            user_data["failed_attempts"] = 0
        user_data["failed_attempts"] += 1
        if user_data["failed_attempts"] >= 3:  # Example: Lock after 3 attempts
            user_data["lockout_time"] = time.time() + 60  # Lock for 60 seconds
            logging.warning(f"Account locked for user: {username}")
        save_config(config)
        return "false"

# --- Example of a more robust regex validation (still not perfect) ---
def validate_password_regex(regex_string):
    """Validates the password regex to prevent injection."""
    # Disallow overly permissive regexes
    if "." in regex_string or "*" in regex_string or "+" in regex_string:
        logging.warning("Password regex contains potentially dangerous characters.  Using default.")
        return r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$"
    # Add more checks as needed
    return regex_string

# --- Example of using predefined password policies ---
PASSWORD_POLICIES = {
    "basic": r"^.{8,}$",  # At least 8 characters
    "medium": r"^(?=.*[a-z])(?=.*\d).{8,}$",  # At least 8 characters, one lowercase, one digit
    "strong": r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$" # Original
}

def get_password_regex_from_policy(policy_name):
    """Returns the password regex for the given policy name."""
    if policy_name in PASSWORD_POLICIES:
        return PASSWORD_POLICIES[policy_name]
    else:
        logging.warning(f"Invalid password policy: {policy_name}. Using default.")
        return PASSWORD_POLICIES["strong"]

# --- Example of Role-Based Access Control (RBAC) ---
# (This would require significant changes to the config file structure)
# Example config.json:
# {
#   "roles": {
#     "administrator": ["read", "write", "admin"],
#     "editor": ["read", "write"],
#     "viewer": ["read"]
#   },
#   "users": {
#     "john": {
#       "salt": "...",
#       "hash": "...",
#       "role": "editor"
#     }
#   }
# }

def has_privilege(username, privilege):
    """Checks if the user has the specified privilege based on their role."""
    config = load_config()
    if "users" in config and username in config["users"]:
        user_data = config["users"][username]
        if "role" in user_data and "roles" in config and user_data["role"] in config["roles"]:
            role = user_data["role"]
            return privilege in config["roles"][role]
    return False

# --- Main section ---
if __name__ == "__main__":
    # Simulate form input
    username = input("Username: ")
    password = input("Password: ")

    # Example of using predefined password policies
    # password_policy = input("Choose password policy (basic, medium, strong): ")
    # password_regex = get_password_regex_from_policy(password_policy)

    # Example of using a validated regex
    # password_regex = load_config().get("password_regex", r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$")
    # password_regex = validate_password_regex(password_regex)

    # ... rest of your code ...

