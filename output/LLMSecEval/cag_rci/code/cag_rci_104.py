try:
    # ... your code ...
except DatabaseError as e:  # Catch specific database exceptions
    app.logger.exception(f"Database error for user ID {session.get('user_id', 'N/A')} at URL {request.url}")
    flash("A database error occurred. Please try again later.", "danger")
except AuthenticationError as e: # Catch specific authentication exceptions
    app.logger.exception(f"Authentication error for user ID {session.get('user_id', 'N/A')} at URL {request.url}")
    flash("Authentication failed. Please try again.", "danger")
except Exception as e:  # Catch other unexpected exceptions
    # Sanitize request.form before logging (Whitelist approach)
    allowed_fields = ['username', 'email', 'product_id', 'quantity']  # Define allowed fields
    safe_form_data = {k: v for k, v in request.form.items() if k in allowed_fields}
    app.logger.exception(f"Unexpected error for user ID {session.get('user_id', 'N/A')} at URL {request.url} with data: {safe_form_data}")
    flash("An unexpected error occurred. Please try again later.", "danger")

