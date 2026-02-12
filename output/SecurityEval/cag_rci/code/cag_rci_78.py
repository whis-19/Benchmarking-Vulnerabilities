# Vulnerable code (example)
    def display_message(message):
        return f"<div>{message}</div>"  # Vulnerable to XSS

    # Secure code (using HTML escaping)
    import html

    def display_message_secure(message):
        escaped_message = html.escape(message)
        return f"<div>{escaped_message}</div>"  # Prevent XSS

