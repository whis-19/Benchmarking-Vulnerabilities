# Example:  A form for performing a specific, safe operation
class CalculationForm(FlaskForm):
    # ... (rest of the form)

@app.route("/calculate", methods=['GET', 'POST'])
@login_required
def calculate():
    # ... (rest of the function)

# Key Differences from the Original (Unsafe) Code:
# 1. No Arbitrary Code Execution: The user cannot provide arbitrary code. Instead, they can only perform a limited set of predefined operations.
# 2. Input Validation: The code validates that the input is in the correct format (numbers), preventing command injection and other vulnerabilities.
# 3. Limited Functionality: The functionality is limited to a specific task (calculation), which reduces the attack surface.

