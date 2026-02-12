LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
    try:
        logging.basicConfig(level=LOG_LEVEL)
    except ValueError:
        logging.error(f"Invalid log level: {LOG_LEVEL}.  Using INFO instead.")
        logging.basicConfig(level=logging.INFO)

