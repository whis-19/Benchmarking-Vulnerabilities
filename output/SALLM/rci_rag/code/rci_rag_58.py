import logging

# Configure logging (e.g., to a file)
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ... inside the evalInput function, in the exception handler:
except Exception as e:
    logging.exception(f"Unexpected error during evaluation: {e}") # Log the full exception
    return "Error: An unexpected error occurred.", 500

