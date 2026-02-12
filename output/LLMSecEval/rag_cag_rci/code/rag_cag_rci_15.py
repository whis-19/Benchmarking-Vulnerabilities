import logging

    app.logger.setLevel(logging.ERROR)  # Or logging.DEBUG for more verbose logging

    try:
        result = get_array_value(index, MY_ARRAY)
    except (IndexError, TypeError) as e:
        error_message = str(e)
        app.logger.error(f"Error accessing array: {e}")

