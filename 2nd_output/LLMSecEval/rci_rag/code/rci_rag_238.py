try:
            os.chmod('config.ini', 0o600)  # Read/write for owner only
            logging.info("Set restrictive permissions on config.ini (600).")
        except OSError as e:
            print("Warning: Could not set restrictive permissions on config.ini.  Please do so manually.")
            logging.warning(f"Could not set restrictive permissions on config.ini: {e}")

