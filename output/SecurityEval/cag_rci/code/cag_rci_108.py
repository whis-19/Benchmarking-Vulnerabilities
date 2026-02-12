import re
import logging
from flask import Flask, request, jsonify, current_app
import concurrent.futures
import os  # For environment variables

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration (can be set via environment variables)
app.config['REGEX_TIMEOUT'] = int(os.environ.get('REGEX_TIMEOUT', 1))  # Default to 1 second
app.config['MAX_REGEX_COMPLEXITY'] = int(os.environ.get('MAX_REGEX_COMPLEXITY', 20)) # Example complexity score
app.config['MAX_TEXT_LENGTH'] = int(os.environ.get('MAX_TEXT_LENGTH', 1024)) # Max text length

# Placeholder for a robust ReDoS mitigation library (replace with a real implementation)
def is_regex_safe(pattern):
    """
    Checks if a regex pattern is safe from ReDoS attacks using a sophisticated analysis.
    This is a placeholder; a real implementation would use a library or complex logic.
    """
    # Example:  Reject patterns with excessive nesting
    if pattern.count('(') > 5:  # Very basic example - improve this!
        logging.warning("Pattern has excessive nesting, potentially unsafe.")
        return False

    # Example: Reject patterns with too many alternations
    if pattern.count('|') > 10: # Very basic example - improve this!
        logging.warning("Pattern has too many alternations, potentially unsafe.")
        return False

    # Example: Blacklist common ReDoS patterns
    redos_patterns = [r"(a+)+$", r"(a|aa)+$"]
    for redos_pattern in redos_patterns:
        if re.search(redos_pattern, pattern):
            logging.warning("Pattern matches a known ReDoS pattern.")
            return False

    # Example: Complexity score (very basic)
    complexity = pattern.count('*') + pattern.count('+') + pattern.count('?') + pattern.count('|')
    if complexity > current_app.config['MAX_REGEX_COMPLEXITY']:
        logging.warning("Pattern exceeds maximum allowed complexity.")
        return False

    return True  # Assume safe for now (replace with actual analysis)


def search_with_timeout(pattern, text, timeout=None):
    """Searches for a pattern in text with a timeout."""
    if timeout is None:
        timeout = current_app.config['REGEX_TIMEOUT']

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(pattern.search, text)
        try:
            result = future.result(timeout)
            return result
        except concurrent.futures.TimeoutError:
            logging.warning("Regex search timed out.")
            return None
        except Exception as e:
            logging.error(f"Regex search error: {e}", exc_info=True) # Log the full exception
            return None

@app.route("/direct", methods=['GET'])
def direct():
    try:
        pattern = request.args.get('pattern')
        text = request.args.get('text')

        if not pattern or not text:
            logging.warning("Missing 'pattern' or 'text' parameter.")
            return jsonify({"error": "Missing 'pattern' or 'text' parameter"}), 400

        # Robust ReDoS mitigation
        if not is_regex_safe(pattern):
            logging.warning("Unsafe pattern provided (ReDoS risk). Pattern: %s", pattern) # Log the pattern
            return jsonify({"error": "Invalid or unsafe pattern"}), 400

        # Sanitize the text input (example: remove HTML tags and limit length)
        # text = re.sub(r'<[^>]+>', '', text) # Example - adapt to your needs
        text = text[:current_app.config['MAX_TEXT_LENGTH']] # Limit text length

        try:
            # Compile the pattern
            compiled_pattern = re.compile(pattern)

            # Search the text with a timeout
            match = search_with_timeout(compiled_pattern, text)

            if match:
                return jsonify({"match": match.group(0)}), 200
            else:
                return jsonify({"match": None}), 200

        except re.error as e:
            logging.warning(f"Regex compilation error (user-provided pattern): {e}. Pattern: {pattern}") # Log the pattern
            return jsonify({"error": f"Invalid regular expression: {e}"}), 400

    except Exception as e:
        logging.exception("An unexpected error occurred.")
        return jsonify({"error": "An unexpected error occurred"}), 500

