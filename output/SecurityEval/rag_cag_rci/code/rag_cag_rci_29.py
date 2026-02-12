import bleach

def filterScriptTags_bleach(content):
    """
    Remove potentially harmful HTML tags and attributes using bleach.
    """
    allowed_tags = bleach.ALLOWED_TAGS  # Start with the default allowed tags
    allowed_tags.remove('script') # Remove script tag from allowed tags

    allowed_attributes = bleach.ALLOWED_ATTRIBUTES # Start with the default allowed attributes

    cleaned_content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes, strip=True)
    return cleaned_content

