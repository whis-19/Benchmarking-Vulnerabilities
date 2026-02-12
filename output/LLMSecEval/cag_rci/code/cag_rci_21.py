class InputValidationError(ValueError):
       pass

   # ...

   if not (re.match(r"^-?\d+$", min_val) and re.match(r"^-?\d+$", max_val)):
       raise InputValidationError("min_val and max_val must be integers.")

