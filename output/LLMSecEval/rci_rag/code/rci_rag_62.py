allowed_tags = ['p', 'a', 'strong', 'em']
    allowed_attributes = {'a': ['href', 'title']}
    username = clean(username, tags=allowed_tags, attributes=allowed_attributes)

