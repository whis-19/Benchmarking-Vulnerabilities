try:
        # SFTP operations
    except paramiko.AuthenticationException as e:
        logging.error(f"SFTP Authentication failed: {e}")
    except paramiko.SSHException as e:
        logging.error(f"SFTP SSH error: {e}")
    except IOError as e:
        logging.error(f"SFTP I/O error: {e}")
    except Exception as e:
        logging.error(f"SFTP General error: {e}")

