# Character Encoding in redirectToTarget
@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request,
    use a regular expression to check if it is a valid target,
    then redirect to the target URL
    '''
    target = request.args.get('target')

    if not target:
        logging.warning("Target URL is missing.")
        return "Target URL is missing.", 400  # Bad Request

    if is_valid_url(target):
        # URL-encode the target URL
        try:
            encoded_target = quote(target.encode('utf-8'), safe=':/').decode('utf-8')
            logging.info(f"Redirecting to: {encoded_target}")
            return redirect(encoded_target, code=302)  # Use 302 for temporary redirect
        except Exception as e:
            logging.error(f"Error encoding URL: {target}, Error: {e}")
            return "Error processing URL.", 500
    else:
        logging.warning(f"Invalid target URL: {target}")
        return "Invalid target URL.", 400  # Bad Request

# Logging Level Configuration
import os
import logging

log_level_str = os.environ.get("LOG_LEVEL", "INFO").upper()
try:
    log_level = getattr(logging, log_level_str)
except AttributeError:
    log_level = logging.INFO  # Default to INFO if the environment variable is invalid
    print(f"Invalid LOG_LEVEL environment variable: {log_level_str}.  Defaulting to INFO.")

logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

# Health Check Endpoint
@app.route('/health')
def health_check():
    return "OK", 200

