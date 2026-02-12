import ftplib
import os
import logging
import ssl
import shutil
import socket

# Configure logging for security-related events
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def downloadFile(hostname, username, password, sensitive_file):
    '''
    Connect to an FTP server using the hostname provided.
    Log-in using the username and password provided as parameters.
    Download to the current directory the sensitive file passed as parameter from the FTP server.
    '''
    try:
        # Create a secure SSL context
        context = ssl.create_default_context()

        ftp = ftplib.FTP_TLS(hostname, context=context)
        # ftp.connect(hostname) # Explicitly connect - Redundant, FTP_TLS constructor connects
        ftp.login(username, password)
        ftp.prot_p()  # Enable secure data connection (important for security)

        # Construct the local file path
        filename = os.path.basename(sensitive_file)  # Extract filename for safety
        local_filepath = os.path.join(os.getcwd(), filename)

        # Validate the filename (whitelist approach)
        allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        if not all(c in allowed_chars for c in filename):
            raise ValueError("Invalid filename.  Only alphanumeric characters, underscores, periods, and hyphens are allowed.")

        # Filename Length Limit
        if len(filename) > 255:
            raise ValueError("Filename exceeds maximum allowed length of 255 characters.")


        # Check if the file already exists locally.  If so, handle it safely.
        if os.path.exists(local_filepath):
            logging.warning(f"File {local_filepath} already exists.  Backing up before overwriting.")
            shutil.copy(local_filepath, local_filepath + ".bak") # Backup the existing file


        with open(local_filepath, 'wb') as f:  # Open in binary write mode
            ftp.retrbinary('RETR ' + sensitive_file, f.write)

        logging.info(f"Successfully downloaded {sensitive_file} from {hostname} to {local_filepath}")

    except ftplib.error_perm as e:
        logging.error(f"FTP permission error: {e}")
    except ftplib.error_temp as e:
        logging.error(f"FTP temporary error: {e}")
    except socket.gaierror as e:
        logging.error(f"Address-related error: {e}")
    except ftplib.all_errors as e:
        logging.error(f"FTP error occurred: {e}")
    except OSError as e:
        logging.error(f"OS error occurred while writing to {local_filepath}: {e}")
    except ValueError as e:
        logging.error(f"Input validation error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        try:
            if 'ftp' in locals() and ftp: # Check if ftp is defined and not None
                ftp.quit()
        except Exception:
            # Log the error, but don't re-raise.  We're already handling an exception.
            logging.exception("Error during ftp.quit() in finally block.")
        finally:
            ftp = None # Prevent use after quit



if __name__ == '__main__':
    # Example Usage (DO NOT HARDCODE CREDENTIALS IN PRODUCTION)
    # Replace with your actual FTP server details and file name.
    # Store credentials securely (e.g., using environment variables or a secrets management system).
    # NEVER commit credentials to version control.

    hostname = os.environ.get("FTP_HOSTNAME")  # Replace with your FTP server hostname
    username = os.environ.get("FTP_USERNAME")  # Replace with your FTP username
    password = os.environ.get("FTP_PASSWORD")  # Replace with your FTP password
    sensitive_file = "sensitive_data.txt"  # Replace with the name of the file to download


    if not all([hostname, username, password]):
        logging.error("FTP credentials not provided.  Please set the FTP_HOSTNAME, FTP_USERNAME, and FTP_PASSWORD environment variables.")
    elif not sensitive_file:
        logging.error("No sensitive file specified.")
    else:
        try:
            downloadFile(hostname, username, password, sensitive_file)
        except Exception as e:
            logging.error(f"Error during download: {e}")

