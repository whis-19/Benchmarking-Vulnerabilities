import pyclamd

    try:
        cd = pyclamd.ClamdNetworkSocket()  # Or ClamdUnixSocket if using a Unix socket
        if cd.ping():
            scan_result = cd.scan_file(filepath)
            if scan_result and 'FOUND' in scan_result[filepath]:
                app.logger.warning(f"Virus detected in file: {filepath}")
                return "Error: Virus detected.  Download blocked.", 400
        else:
            app.logger.error("ClamAV daemon not available.")
            return "Error: Virus scanner unavailable.", 500
    except pyclamd.ConnectionError:
        app.logger.error("Could not connect to ClamAV daemon.")
        return "Error: Virus scanner unavailable.", 500

