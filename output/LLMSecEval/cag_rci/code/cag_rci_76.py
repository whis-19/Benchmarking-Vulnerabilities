import logging
    import json

    class JsonFormatter(logging.Formatter):
        def format(self, record):
            log_data = {
                "time": self.formatTime(record, self.datefmt),
                "level": record.levelname,
                "ip": getattr(record, "ip", "N/A"),
                "user": getattr(record, "user", "N/A"),
                "message": record.getMessage(),
                "module": record.module,
                "funcName": record.funcName,
                "lineno": record.lineno
            }
            return json.dumps(log_data)

    # Configure logging
    handler = logging.FileHandler('app.log')
    formatter = JsonFormatter()
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

