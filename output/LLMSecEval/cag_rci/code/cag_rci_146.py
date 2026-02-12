@app.after_request
def add_csp_header(response):
    """Adds Content Security Policy header to the response."""
    # Nonces and hashes are crucial for allowing inline scripts and styles while still maintaining a strong CSP.
    # THIS CSP IS VERY RESTRICTIVE AND LIKELY NEEDS ADJUSTMENT FOR A REAL APPLICATION.
    # You'll need to analyze your application's dependencies and add the necessary
    # script-src, style-src, img-src, font-src, etc. directives.
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self';"  # Adjust as needed
    return response

# Sample array (replace with your actual data - ideally from a database or config)
# FOR PRODUCTION, THIS SHOULD BE LOADED FROM A DATABASE TO AVOID STORING SENSITIVE DATA IN CODE.
data_array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

@app.route('/', methods=['GET', 'POST'])
def index():
    form = InputForm()
    result = None

    if form.validate_on_submit():
        index = form.index.data
        try:
            result = data_array[index]
        except IndexError:
            # Ensure the flash message is properly escaped to prevent XSS.
            # For example, if data_array contained user-supplied data, an attacker could inject HTML.
            flash("Invalid index. Please enter a value between 0 and {}".format(len(data_array) - 1), 'error')
            result = None
        except Exception as e:  # Consider more specific exception handling
            app.logger.exception("An unexpected error occurred:") # Log the full exception, including the stack trace
            flash("An unexpected error occurred. Please check the logs.", 'error') # Generic error message for the user
            result = None

    return render_template('index.html', form=form, result=result)
    # REMEMBER TO INCLUDE THE CSRF TOKEN IN THE index.html TEMPLATE: {{ form.csrf_token }}

