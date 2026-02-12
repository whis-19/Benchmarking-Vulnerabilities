import logging

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    try:
        # ... your code ...
    except Exception as e:
        logging.error(f"Error processing file: {e}", exc_info=True) # Log with traceback
        return jsonify({'error': 'An error occurred while processing the file.'}, 500)

