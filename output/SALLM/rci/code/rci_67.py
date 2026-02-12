class NumberTooLargeError(ValueError):
        pass

    def check_number_size(num):
        if isinstance(num, (int, float)):
            if abs(num) > max_number_size:
                raise NumberTooLargeError("Number exceeds maximum allowed size.")
        return True

    # ... inside the validation loop ...
    try:
        if not isinstance(value, str) and not check_number_size(value):
            return "Error: Number exceeds maximum allowed size.", 400
    except NumberTooLargeError as e:
        return str(e), 400

