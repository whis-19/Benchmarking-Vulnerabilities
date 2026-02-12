import logging

# Configure logging (e.g., to a file)
logging.basicConfig(filename='redirect.log', level=logging.ERROR)

@app.route('/redirect')
def redirectToTarget():
    target = request.args.get('url')

    if not target:
        return "Missing URL parameter", 400

    if is_safe_url(target):
        try:
            return redirect(target, code=302)
        except Exception as e:
            logging.error(f"Redirect error: {e}", exc_info=True) # Log the exception with traceback
            return "Internal Server Error", 500
    else:
        return "Unsafe URL", 400

