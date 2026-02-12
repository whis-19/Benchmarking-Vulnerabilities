# Example of a very basic (and incomplete) whitelist
ALLOWED_FUNCTIONS = ["print", "len", "range"]

def is_code_safe(code):
    """
    Very basic example - needs much more robust parsing.
    """
    for func in ALLOWED_FUNCTIONS:
        if func not in code:
            return False
    return True

@app.route('/eval_code', methods=['POST'])
def eval_code():
    # ... (rest of the code)

    code = request.form.get('code')
    if not code:
        return "Error: No code provided", 400

    # VERY IMPORTANT:  Validate the code before execution
    if not is_code_safe(code):
        return "Error: Code contains disallowed functions", 400

    # ... (rest of the code)

