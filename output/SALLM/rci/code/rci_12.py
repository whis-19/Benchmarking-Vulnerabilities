log_file = 'my_application.log'
    log_level = logging.DEBUG  # Or logging.INFO, logging.WARNING for production

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=1024*1024,  # 1MB
                backupCount=5
            )
        ]
    )

