import ftplib
import os
import logging
import time
from urllib.parse import urlparse
import hashlib
import json  # For persistent login attempts
import socket  # For socket errors
import validators  # For hostname validation
import ssl # For certificate verification

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting parameters (adjust as needed)
LOGIN_ATTEMPT_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPTS_FILE = "login_attempts.json"  # File to store login attempts
login_attempts = {}  # Store login attempts per IP/user (IP is now included)

# Maximum file size (in bytes)
MAX_FILE_SIZE = 1024 * 1024 * 100  # 100 MB

# Configuration option to disable rate limiting
DISABLE_RATE_LIMITING = False  # Set to True in trusted environments

def load_login_attempts():
    """Loads login attempts from file."""
    global login_attempts
    try:
        with open(LOGIN_ATTEMPTS_FILE, "r") as f:
            login_attempts = json.load(f)
    except FileNotFoundError:
        login_attempts = {}
    except json.JSONDecodeError:
        logging.warning("Error decoding login attempts file.  Starting with empty attempts.")
        login_attempts = {}

def save_login_attempts():
    """Saves login attempts to file."""
    try:
        with open(LOGIN_ATTEMPTS_FILE, "w") as f:
            json.dump(login_attempts, f)
    except (IOError, OSError, json.JSONEncodeError) as e:  # More specific exception handling
        logging.error(f"Error saving login attempts: {e}")

def is_path_traversal(path):
    """
    Checks if the path contains path traversal sequences like ../
    """
    normalized_path = os.path.normpath(path)
    return ".." in normalized_path


def is_allowed_file_extension(filename, allowed_extensions):
    """
    Checks if the file extension is in the allowlist.
    """
    _, ext = os.path.splitext(filename)
    return ext.lower() in allowed_extensions


def downloadFile(hostname, username, password, sensitive_file, ip_address, download_location=None, allowed_extensions=None, allowed_download_locations=None, known_good_hash=None):
    """
    Connect to an FTP server using the hostname provided.
    Log-in using the username and password provided as parameters.
    Download to the specified directory the sensitive file passed as parameter from the FTP server.

    Security Considerations:
    - Rate limiting for login attempts (now includes IP address).
    - Account lockout after too many failed attempts.
    - Path traversal prevention.
    - File extension allowlist.
    - Allowed download locations.
    - Secure file permissions (umask).
    - Hash verification.
    - Certificate verification (TLS/SSL).
    """

    # Input Validation
    if not hostname or not username or not password or not sensitive_file or not ip_address:
        logging.error("Missing required parameters.")
        return False

    if not validators.domain(hostname) and not validators.ipv4(hostname) and not validators.ipv6(hostname):
        logging.error("Invalid hostname.")
        return False

    # Rate Limiting and Account Lockout
    if not DISABLE_RATE_LIMITING:
        key = (ip_address, username)  # Use IP and username as the key
        now = time.time()
        if key in login_attempts:
            attempts, last_attempt, locked = login_attempts[key]
            if locked:
                logging.warning(f"Account locked for IP: {ip_address}, user: {username}")
                return False
            if now - last_attempt < LOGIN_ATTEMPT_WINDOW and attempts >= MAX_LOGIN_ATTEMPTS:
                logging.warning(f"Rate limit exceeded for IP: {ip_address}, user: {username}")
                login_attempts[key] = (attempts, last_attempt, True)  # Lock the account
                save_login_attempts()
                return False
            elif now - last_attempt >= LOGIN_ATTEMPT_WINDOW:
                login_attempts[key] = (1, now, False)  # Reset attempts and unlock
            else:
                login_attempts[key] = (attempts + 1, now, False)
        else:
            login_attempts[key] = (1, now, False)
        save_login_attempts()

    # Path Traversal Prevention
    if is_path_traversal(sensitive_file):
        logging.error("Path traversal detected in filename.")
        return False

    # File Extension Allowlist (if provided)
    if allowed_extensions and not is_allowed_file_extension(sensitive_file, allowed_extensions):
        logging.error(f"File extension not allowed for: {sensitive_file}")
        return False

    # Allowed Download Locations (if provided)
    if download_location is None:
        download_location = os.getcwd()  # Default to current directory
    else:
        download_location = os.path.abspath(download_location)  # Normalize the path

    if allowed_download_locations:
        allowed = False
        for allowed_location in allowed_download_locations:
            allowed_location = os.path.abspath(allowed_location)
            if os.path.commonpath([download_location, allowed_location]) == allowed_location:
                allowed = True
                break
        if not allowed:
            logging.error(f"Download location not allowed: {download_location}")
            return False

    try:
        # FTP Connection with Explicit TLS/SSL and Certificate Verification
        context = ssl.create_default_context()
        context.check_hostname = True  # Enable hostname verification (recommended)
        context.verify_mode = ssl.CERT_REQUIRED  # Require certificate verification

        ftp = ftplib.FTP_TLS(hostname, context=context)
        ftp.login(username, password)
        ftp.prot_p() # Enable secure data connection (TLS/SSL)

        # Get file size before downloading
        try:
            file_size = ftp.size(sensitive_file)
            if file_size > MAX_FILE_SIZE:
                logging.error(f"File size exceeds maximum allowed size: {file_size} > {MAX_FILE_SIZE}")
                ftp.quit()
                return False
        except Exception as e:
            logging.warning(f"Could not determine file size: {e}")  # Non-critical error

        # Download File
        local_filename = os.path.join(download_location, os.path.basename(sensitive_file))  # Ensure basename for safety

        # Check if the file already exists and handle it (e.g., overwrite, rename, skip)
        if os.path.exists(local_filename):
            logging.warning(f"File already exists: {local_filename}.")
            action = input("File already exists. (R)ename, (S)kip, (O)verwrite? ").lower()
            if action == 'r':
                # Suggest a new filename (e.g., append timestamp)
                timestamp = time.strftime("%Y%m%d%H%M%S")
                new_filename = f"{os.path.splitext(local_filename)[0]}_{timestamp}{os.path.splitext(local_filename)[1]}"
                local_filename = new_filename
                logging.info(f"Renaming file to: {local_filename}")
            elif action == 's':
                logging.info("Skipping download.")
                ftp.quit()
                return False
            elif action == 'o':
                logging.warning("Overwriting existing file.")
            else:
                logging.warning("Invalid action. Skipping download.")
                ftp.quit()
                return False

        # Calculate SHA-256 hash while downloading
        hasher = hashlib.sha256()
        with open(local_filename, 'wb') as f:
            def write_and_hash(data):
                f.write(data)
                hasher.update(data)

            ftp.retrbinary('RETR ' + sensitive_file, write_and_hash)

        # Secure File Permissions (umask) - important for shared systems
        os.umask(0o077)  # Set restrictive permissions (owner only read/write)
        os.chmod(local_filename, 0o600)  # Explicitly set file permissions

        # Verify the hash (replace with your known good hash)
        downloaded_file_hash = hasher.hexdigest()
        if known_good_hash and downloaded_file_hash != known_good_hash:  # UNCOMMENT THIS!
            logging.error(f"File integrity check failed. Hash mismatch: {downloaded_file_hash} != {known_good_hash}")
            os.remove(local_filename)  # Remove the potentially corrupted file
            return False

        logging.info(f"File downloaded successfully: {local_filename}")
        ftp.quit()
        return True

    except ftplib.error_perm as e:
        logging.error(f"FTP permission error: {e}")
        return False
    except ftplib.error_temp as e:
        logging.error(f"FTP temporary error: {e}")
        # Implement retry logic here
        return False
    except socket.gaierror as e:
        logging.error(f"Hostname resolution error: {e}")
        return False
    except ftplib.all_errors as e:
        logging.error(f"FTP error: {e}")
        return False
    except OSError as e:
        logging.error(f"OS error: {e}")
        return False
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
        return False
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Use exception for full traceback
        return False
    finally:
        # Reset login attempts on success or failure (after a delay to prevent brute-forcing)
        if not DISABLE_RATE_LIMITING:
            time.sleep(1)  # Small delay
            if key in login_attempts:
                del login_attempts[key]
                save_login_attempts()  # Save login attempts to file


# Example Usage (replace with your actual values - DO NOT HARDCODE CREDENTIALS)
if __name__ == '__main__':
    # Load login attempts from file
    load_login_attempts()

    # NEVER HARDCODE CREDENTIALS!  Use environment variables, configuration files, or a secrets management system.
    hostname = os.environ.get("FTP_HOSTNAME")
    username = os.environ.get("FTP_USERNAME")
    password = os.environ.get("FTP_PASSWORD")
    sensitive_file = "sensitive_data.txt"  # Replace with the actual filename on the FTP server
    ip_address = "127.0.0.1"  # Replace with the actual IP address (e.g., from request object)

    # Define allowed file extensions and download locations
    allowed_extensions = {".txt", ".csv", ".pdf"}
    allowed_download_locations = [os.getcwd(), "/tmp/safe_downloads"]  # Example
    download_location = "/tmp/safe_downloads" # Example download location

    # Retrieve the known-good hash from a secure source (e.g., environment variable)
    known_good_hash = os.environ.get("SENSITIVE_FILE_HASH")  # Example

    if hostname and username and password:
        success = downloadFile(hostname, username, password, sensitive_file, ip_address, download_location, allowed_extensions, allowed_download_locations, known_good_hash)
        if success:
            print("File downloaded successfully.")
        else:
            print("File download failed.")
    else:
        print("FTP credentials not found in environment variables.")

