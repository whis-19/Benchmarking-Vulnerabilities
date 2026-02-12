import re

    def sanitize_email(email):
        """Removes control characters from the email address."""
        return re.sub(r"[\x00-\x1F\x7F]", "", email)

    # ... in the unsubscribe function:
    email = request.args.get('email')
    if not email:
        logging.warning("Unsubscribe request missing email parameter.")
        return jsonify({'error': 'Email parameter is required'}), 400

    try:
        email = unquote(email)
    except Exception as e:
        logging.error(f"Error decoding email: {e}")
        return jsonify({'error': 'Invalid email format'}), 400

    email = sanitize_email(email)  # Sanitize before validation

    if not is_valid_email(email):
        logging.warning(f"Invalid email format: {email}")
        return jsonify({'error': 'Invalid email format'}), 400

