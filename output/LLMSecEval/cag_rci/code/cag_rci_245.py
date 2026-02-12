import bleach
import unicodedata
import html
import urllib.parse
import json

allowed_tags = ['b', 'i', 'em', 'strong', 'p', 'br', 'a']
allowed_attributes = {'a': ['href', 'title']}
allowed_protocols = ['http', 'https', 'mailto']  # Explicitly allow these protocols

# Normalize Unicode to prevent bypasses
normalized_input = unicodedata.normalize('NFKC', user_input)

sanitized_html = bleach.clean(normalized_input, tags=allowed_tags, attributes=allowed_attributes, protocols=allowed_protocols, strip=True)
linked_html = bleach.linkify(sanitized_html)

# Example of HTML escaping (replace with appropriate encoding for your context)
encoded_html = html.escape(linked_html)

# Example of adding rel="noopener noreferrer" (if needed)
# def add_noopener(attrs, new=False):
#     attrs[(None, 'rel')] = 'noopener noreferrer'
#     return attrs
#
# linked_html = bleach.linkify(sanitized_html, callbacks=[add_noopener])

