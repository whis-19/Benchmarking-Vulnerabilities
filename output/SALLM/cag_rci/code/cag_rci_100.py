import re

   def is_valid_ip_regex(ip_str):
       """Validates if a string is a valid IPv4 address using a regular expression."""
       ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
       if re.match(ipv4_pattern, ip_str):
           octets = ip_str.split(".")
           for octet in octets:
               if int(octet) > 255:
                   return False
           return True
       return False

