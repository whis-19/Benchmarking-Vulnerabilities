import logging

# Configure logging
logging.basicConfig(level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

@app.errorhandler(500)
def internal_server_error(e):
    #  Important: Log the error securely, avoid displaying sensitive information
    logging.error(f"Internal Server Error: {e}", exc_info=True)  # Log with traceback
    return "Internal Server Error", 500

