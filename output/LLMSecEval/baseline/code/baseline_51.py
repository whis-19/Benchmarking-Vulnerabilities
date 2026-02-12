from url_redirector import URLRedirector

redirector = URLRedirector(r"^https://mywebsite\.com/products/.*$", "https://mywebsite.com/sale")
redirect_url = redirector.get_redirect_url("https://mywebsite.com/products/widget123")
print(redirect_url)  # Output: https://mywebsite.com/products/widget123

redirect_url = redirector.get_redirect_url("https://mywebsite.com/about")
print(redirect_url)  # Output: https://mywebsite.com/sale

