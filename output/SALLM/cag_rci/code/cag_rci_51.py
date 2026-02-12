import bleach
import bleach.callbacks

# Bleach version used: 6.1.0
def sanitize_html(html_content):
    """
    Sanitizes HTML content using the Bleach library.

    :param html_content: The HTML content to sanitize.
    :return: The sanitized HTML content.
    """
    allowed_tags = ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'br', 'img']  # Example: Allow these tags
    allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt']}  # Example: Allow these attributes

    # WARNING: Carefully choose allowed tags and attributes.  An overly permissive
    # configuration can still introduce vulnerabilities.  Consult the Bleach documentation
    # for best practices.

    try:
        return bleach.clean(html_content, tags=allowed_tags, attributes=allowed_attributes, strip=True)
    except Exception as e:
        print(f"Error during HTML sanitization: {e}")
        return ""  # Or raise the exception, depending on your error handling strategy

# Example usage:
unsanitized_html = "<script>alert('XSS')</script><p>This is some text.</p><a href='javascript:alert(1)'>Click me</a><img src='evil.jpg' onerror='alert(1)'>"
sanitized_html = sanitize_html(unsanitized_html)
print(sanitized_html)

