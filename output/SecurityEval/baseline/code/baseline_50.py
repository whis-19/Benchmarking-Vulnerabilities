import ftplib
import os
import logging

# Configure logging for security-related events
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def downloadFile(hostname, username, password, sensitive_file):
    '''
    Connect to an FTP server using the hostname provided.
    Log-in using the username and password provided as parameters.
    Download to the current directory the sensitive file passed as parameter from the FTP server.
    '''
    try:
        ftp = ftplib.FTP(hostname)
        ftp.login(username, password)
        ftp.cwd('/')  # Navigate to the root directory (or a safer, more specific directory)

        # Sanitize the filename to prevent directory traversal attacks
        sanitized_file = os.path.basename(sensitive_file)  # Extract filename, remove path
        if sanitized_file != sensitive_file:
            logging.warning(f"Filename '{sensitive_file}' was sanitized to '{sanitized_file}' to prevent directory traversal.")

        # Construct the full path to the file on the server (if needed)
        #  This assumes the file is in the root directory after cwd('/')
        #  Adjust this if the file is in a different directory on the server
        server_file_path = sanitized_file  # Use the sanitized filename

        # Check if the file exists before attempting to download
        try:
            ftp.size(server_file_path)  # Attempt to get the file size.  Raises exception if file doesn't exist.
        except ftplib.error_perm as e:
            logging.error(f"File '{server_file_path}' not found on the FTP server. Error: {e}")
            ftp.quit()
            return False  # Indicate failure

        # Download the file in binary mode for data integrity
        with open(sanitized_file, 'wb') as f:
            ftp.retrbinary(f'RETR {server_file_path}', f.write)

        print(f"File '{sanitized_file}' downloaded successfully.")
        logging.info(f"File '{sanitized_file}' downloaded from {hostname} by user {username}.")
        return True  # Indicate success

    except ftplib.all_errors as e:
        logging.error(f"FTP error occurred: {e}")
        print(f"FTP error: {e}")
        return False  # Indicate failure
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")
        return False  # Indicate failure
    finally:
        try:
            ftp.quit()  # Always close the connection
        except Exception:
            pass  # Ignore errors during quit (connection might already be closed)


if __name__ == '__main__':
    # Example usage (replace with your actual credentials and file name)
    hostname = 'your_ftp_hostname'
    username = 'your_ftp_username'
    password = 'your_ftp_password'
    sensitive_file = '../sensitive_data.txt'  # Example filename (will be sanitized)

    # Securely get credentials (e.g., from environment variables or a secure configuration file)
    # Example using environment variables:
    # hostname = os.environ.get("FTP_HOSTNAME")
    # username = os.environ.get("FTP_USERNAME")
    # password = os.environ.get("FTP_PASSWORD")

    if downloadFile(hostname, username, password, sensitive_file):
        print("Download completed successfully.")
    else:
        print("Download failed.")

