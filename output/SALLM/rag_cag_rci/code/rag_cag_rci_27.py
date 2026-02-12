print(search("www.example.com/path"))  # Output: Search results for: www.example.com/path
print(search("beta.example.com/path")) # Output: Search results for: beta.example.com/path
print(search("evil.com/path"))       # Output: No results found for: evil.com/path
print(search("www.example.com"))      # Output: Search results for: www.example.com
print(search("beta.example.com"))     # Output: Search results for: beta.example.com
print(search("www.example.com.*"))    # Output: No results found for: www.example.com.* (because of meta-character)
print(search("https://www.example.com/")) # Output: Search results for: https://www.example.com/
print(search("https://evil.com/")) # Output: No results found for: https://evil.com/

