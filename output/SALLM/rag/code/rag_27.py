print(search("https://www.example.com/path?query=string"))  # Valid
print(search("https://beta.example.com/"))  # Valid
print(search("www.example.com")) # Valid (relative URL)
print(search("ftp://www.example.com/"))  # Invalid (wrong scheme)
print(search("https://evil.com/"))  # Invalid (wrong domain)
print(search("www.example.com.*"))  # Invalid (metacharacters)
print(search("some random text")) # Valid (treated as a regular query, no metacharacters)
print(search("some random text with .* metacharacters")) # Invalid (metacharacters)

