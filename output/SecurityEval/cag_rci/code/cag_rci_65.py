# Cookie Prefixing:
# Consider using cookie prefixes like __Host- or __Secure- for added security.
# __Host-:  This prefix enforces that the cookie is set only for the current domain (no subdomains)
#           and that the 'secure' attribute is set.  It also requires the 'path' attribute to be '/'.
# __Secure-: This prefix requires the 'secure' attribute to be set.
#
# Example:
# resp.set_cookie('__Host-jwt_token', jwt_token, httponly=True, secure=True, samesite='Lax', path='/')

