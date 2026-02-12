import openai
import os
import logging
from typing import List
import tiktoken  # For token counting
import time
# from flask_limiter import Limiter  # Removed Flask-Limiter dependency
# from flask_limiter.util import get_remote_address # Removed Flask-Limiter dependency
import secrets  # For generating API keys
import hashlib  # For hashing API keys
from collections import defaultdict  # For simpler rate limiting
import threading  # For thread safety in rate limiting

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Securely retrieve the API key from an environment variable
openai.api_key = os.environ.get("OPENAI_API_KEY")

# Validate that the API key is set
if not openai.api_key:
    logging.error("OPENAI_API_KEY environment variable must be set.")
    raise ValueError("OPENAI_API_KEY environment variable must be set.")

# Constants
EMBEDDING_MODEL = "text-embedding-ada-002"
MAX_INPUT_TOKENS = 8191  # Maximum tokens supported by the embedding model
RATE_LIMIT_RETRY_DELAY = 10  # Seconds to wait before retrying after a rate limit error
MAX_RETRIES = 3  # Maximum retry attempts
MAX_INPUT_LENGTH = 10000  # Maximum characters in the input text (arbitrary limit)

# --- Authentication and Authorization ---
# Store API keys (in a real application, use a database or secrets management system)
# API keys should be hashed before storing
API_KEYS = {
    hashlib.sha256("your_api_key_1".encode()).hexdigest(): {"role": "user"},  # Example user API key
    hashlib.sha256("your_api_key_2".encode()).hexdigest(): {"role": "admin"}   # Example admin API key
}

# --- Rate Limiting (Simple In-Memory Implementation) ---
# In a production environment, use Redis or another distributed cache
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 10  # requests per window
user_request_counts = defaultdict(int)
user_request_timestamps = defaultdict(list)
rate_limit_lock = threading.Lock()  # Ensure thread safety

def generate_api_key():
    """Generates a new API key."""
    return secrets.token_urlsafe(32)

def hash_api_key(api_key: str) -> str:
    """Hashes an API key using SHA-256."""
    return hashlib.sha256(api_key.encode()).hexdigest()

def authenticate_api_key(api_key: str) -> str | None:
    """Authenticates an API key and returns the user role if valid, otherwise None."""
    hashed_api_key = hash_api_key(api_key)
    if hashed_api_key in API_KEYS:
        return API_KEYS[hashed_api_key]["role"]
    return None

def is_rate_limited(api_key: str) -> bool:
    """Checks if the API key is rate limited."""
    with rate_limit_lock:
        now = time.time()
        timestamps = user_request_timestamps[api_key]
        # Remove timestamps older than the rate limit window
        timestamps = [ts for ts in timestamps if now - ts < RATE_LIMIT_WINDOW]
        user_request_timestamps[api_key] = timestamps
        # Check if the number of requests exceeds the limit
        if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
            return True
        else:
            return False

def record_request(api_key: str):
    """Records a request for the given API key."""
    with rate_limit_lock:
        user_request_counts[api_key] += 1
        user_request_timestamps[api_key].append(time.time())

def num_tokens_from_string(string: str, encoding_name: str) -> int:
    """Returns the number of tokens in a text string."""
    encoding = tiktoken.get_encoding(encoding_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens

def sanitize_for_database(text: str) -> str:
    """
    Sanitizes the input text to prevent SQL injection if the embeddings are stored in a database.
    This is a placeholder; adapt to your specific database and ORM.
    """
    # Example: Escape single quotes
    return text.replace("'", "''")

def get_embeddings(text: str, api_key: str, retry_count: int = 0) -> List[float]:
    '''
    Calculate the embeddings for the text provided as parameter using the OpenAI's 'text-embedding-ada-002' model.
    Then, return a list of the embeddings.

    Args:
        text: The text to generate embeddings for.
        api_key: The API key for authentication and rate limiting.

    Returns:
        A list of floats representing the embeddings.  Returns an empty list if an error occurs.
    '''

    # --- Authentication ---
    user_role = authenticate_api_key(api_key)
    if not user_role:
        logging.warning(f"Authentication failed for API key: {api_key}")
        return []  # Or raise an exception

    # --- Authorization (Example - restrict input length for non-admin users) ---
    if user_role != "admin" and len(text) > MAX_INPUT_LENGTH // 2:  # Example: Non-admins have shorter limit
        logging.warning(f"Input text too long for user role '{user_role}'.  Maximum length: {MAX_INPUT_LENGTH // 2}")
        return []

    # Input Validation
    if not isinstance(text, str):
        logging.error(f"Invalid input: Text must be a string.  Got {type(text)}")
        return []

    if len(text) > MAX_INPUT_LENGTH:
        logging.warning(f"Input text exceeds maximum length ({MAX_INPUT_LENGTH}).")
        return [] # Reject input that's too long

    num_tokens = num_tokens_from_string(text, "cl100k_base")  # Correct encoding for ada-002
    if num_tokens > MAX_INPUT_TOKENS:
        logging.warning(f"Input text exceeds maximum token limit ({MAX_INPUT_TOKENS}).")
        return [] # Reject input that's too long

    # --- Contextual Sanitization (Example for Database Storage) ---
    sanitized_text = sanitize_for_database(text)

    # --- Rate Limiting ---
    if is_rate_limited(api_key):
        logging.warning(f"Rate limit exceeded for API key: {api_key}")
        return []  # Or raise an exception

    try:
        record_request(api_key)  # Record the request *before* making the API call

        response = openai.Embedding.create(
            input=[sanitized_text],  # Use the sanitized text
            model=EMBEDDING_MODEL
        )

        embeddings = response['data'][0]['embedding']
        return embeddings

    except openai.error.RateLimitError as e:
        if retry_count < MAX_RETRIES:
            logging.warning(f"OpenAI RateLimitError: {e}.  Retrying after {RATE_LIMIT_RETRY_DELAY} seconds. Attempt {retry_count + 1}/{MAX_RETRIES}")
            time.sleep(RATE_LIMIT_RETRY_DELAY)
            return get_embeddings(text, api_key, retry_count + 1)  # Retry the request
        else:
            logging.error(f"OpenAI RateLimitError: Max retries reached. Aborting.")
            return []

    except openai.error.APIConnectionError as e:
        logging.error(f"OpenAI API Connection Error: {e}")
        return []  # Return an empty list in case of an error

    except openai.error.AuthenticationError as e:
        logging.error(f"OpenAI Authentication Error: {e}.  Check your API key.")
        return []

    except openai.error.OpenAIError as e:
        logging.error(f"OpenAI API Error: {e}")
        return []  # Return an empty list in case of an error

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception traceback
        return []  # Return an empty list in case of an error


if __name__ == '__main__':
    # Example usage:
    api_key = "your_api_key_1"  # Replace with a valid API key
    hashed_api_key = hash_api_key(api_key)

    text_to_embed = "This is a sample sentence.  <script>alert('XSS');</script>  ' OR 1=1 --"  # Example with potential XSS and SQL injection
    embeddings = get_embeddings(text_to_embed, api_key)

    if embeddings:
        print(f"Embeddings for '{text_to_embed}':")
        print(embeddings[:10], "...") # Print only the first 10 elements for brevity
        print(f"Length of embeddings: {len(embeddings)}")
    else:
        print("Failed to generate embeddings.")

    # Example of generating a new API key (for demonstration purposes only)
    new_api_key = generate_api_key()
    print(f"Generated API Key (DO NOT STORE THIS IN CODE): {new_api_key}")
    hashed_new_api_key = hash_api_key(new_api_key)
    print(f"Hashed API Key (Store this securely): {hashed_new_api_key}")

