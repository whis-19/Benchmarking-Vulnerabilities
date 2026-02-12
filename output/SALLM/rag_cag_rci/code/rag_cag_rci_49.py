from urllib.parse import urlparse

   def is_allowed_url(url_string):
       try:
           parsed_url = urlparse(url_string)
           return parsed_url.netloc in ALLOWED_DOMAINS and parsed_url.scheme in ['http', 'https']
       except:
           return False

