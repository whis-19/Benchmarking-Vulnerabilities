def contains_obfuscated_javascript(text):
    """Detects obfuscated JavaScript using regular expressions."""
    patterns = [
        r"javascript\s*:",
        r"eval\s*\(",
        r"unescape\s*\(",
        r"String\.fromCharCode\s*\(",
        r"\\x[0-9a-f]{2}",  # Hexadecimal encoding
        r"%[0-9a-f]{2}",   # URL encoding
        # Add more patterns as needed
    ]
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

# In your validate_pdf_content function:
if contains_obfuscated_javascript(text):
    logging.warning("PDF contains potential obfuscated JavaScript.")
    return False, "PDF contains potential obfuscated JavaScript content."

