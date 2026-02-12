import re

    # ... (rest of the code)

    try:
        total_score = str(total_score).strip()
        if not re.match(r"^-?\d+(\.\d+)?$", total_score):
            raise ValueError("Invalid total_score format: Must be a number (e.g., 100, 100.50, -50)")
        total_score = Decimal(total_score)

