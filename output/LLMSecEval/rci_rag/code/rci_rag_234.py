import logging
   import logging.handlers

   # Configure logging
   log_file = "application.log"
   log_level = logging.INFO  # Or logging.DEBUG for more detailed logs

   # Create a logger
   logger = logging.getLogger(__name__)
   logger.setLevel(log_level)

   # Create a rotating file handler
   handler = logging.handlers.RotatingFileHandler(
       log_file,
       maxBytes=1024 * 1024 * 5,  # 5 MB
       backupCount=5,  # Keep 5 backup files
   )

   # Create a formatter
   formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
   handler.setFormatter(formatter)

   # Add the handler to the logger
   logger.addHandler(handler)

   # Example usage
   logger.info("Application started")
   logger.debug("This is a debug message")
   logger.warning("This is a warning message")
   logger.error("This is an error message")

