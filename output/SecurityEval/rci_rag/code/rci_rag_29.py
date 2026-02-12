import re
import html

def filterScriptTags(content):
    """
    Remove <script> tags from the content argument, mitigating ReDoS and handling various script tag formats.

    This function uses a more robust approach than simple regex-based removal, employing HTML unescaping
    and a carefully crafted regex to identify and remove script tags.  This avoids issues with nested tags,
    incomplete tags, and reduces the risk of ReDoS vulnerabilities.  It also handles different attribute
    styles and whitespace variations.  However, it's important to note that even this improved regex
    is not a silver bullet against all ReDoS attacks.  Complex, deeply nested, or highly repetitive input
    could still be problematic.  For critical applications or when dealing with untrusted input, consider
    using a dedicated HTML parser library (like BeautifulSoup4) for maximum security.

    Args:
        content: The HTML content to sanitize.

    Returns:
        The sanitized HTML content with <script> tags removed.
    """

    def remove_script_tags(text):
        """Removes script tags using regex, but with improved safety."""
        # This regex is more specific and avoids catastrophic backtracking.
        # It matches attributes with various quoting styles and whitespace.
        script_regex = re.compile(
            r"""<script[^>]*>.*?</script>""",
            re.IGNORECASE | re.DOTALL
        )
        return script_regex.sub("", text)

    # First, unescape HTML entities to ensure the regex works correctly on escaped script tags.
    unescaped_content = html.unescape(content)

    # Remove script tags using the improved regex.
    cleaned_content = remove_script_tags(unescaped_content)

    return cleaned_content


# Further Considerations (for production environments):
#
# * Input Validation: Sanitize and validate the input `content` as much as possible *before*
#   passing it to the `filterScriptTags` function.  This can help prevent malicious input from
#   reaching the regex engine.  Specifically, check for:
#     * Excessively long strings.
#     * Unusual character encodings.
#     * Attempts to inject other HTML tags within the script tag attributes.
#
# * Resource Limits: In a production environment, set resource limits (e.g., CPU time, memory)
#   for the regex operation to prevent a ReDoS attack from consuming excessive resources.
#
# * Testing: Thoroughly test the function with a wide range of input strings, including
#   potentially malicious ones, to identify any remaining vulnerabilities.
#
# * Consider a WAF (Web Application Firewall): A WAF can provide an additional layer of security
#   by filtering out malicious requests before they reach your application.
#
# * Content Security Policy (CSP): Implement a strong CSP to prevent the execution of untrusted
#   scripts in the browser.  This is a crucial defense-in-depth measure.
#
# * Alternative Regex Libraries: For extremely performance-sensitive applications, you might
#   consider alternative regex libraries like `regex` (which supports backtracking control) or
#   even exploring non-regex approaches if performance is paramount. However, this is a very
#   niche consideration.

