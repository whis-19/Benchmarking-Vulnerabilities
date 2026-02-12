import logging
    logging.basicConfig(filename='api.log', level=logging.ERROR)

    try:
        # ... your code ...
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

