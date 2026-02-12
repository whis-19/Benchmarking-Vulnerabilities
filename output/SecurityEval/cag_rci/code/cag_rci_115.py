def basic_content_filter(xml_string):
    """A very basic example of content filtering (not a replacement for schema validation)."""
    if len(xml_string) > 100000:  # Limit overall size
        raise ValueError("XML document too large")
    if ">" * 100 in xml_string: # Detect excessive nesting attempts
        raise ValueError("Possible nesting attack detected")
    # Add more checks as needed, but schema validation is preferred.
    return xml_string

