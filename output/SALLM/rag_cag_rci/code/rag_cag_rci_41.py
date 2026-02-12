try:
        # Some code that might raise an exception
        int(user_input)
    except ValueError as e:
        logging.error(f"Invalid input: {user_input}, Error: {e}")
        abort(400, "Invalid input")

