import openai
import os
import hashlib
import secrets
import json
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# API Key (Ideally, load this from an environment variable or secure storage)
# NEVER hardcode your API key directly in the code.
openai.api_key = os.environ.get("OPENAI_API_KEY")

# Model to use
EMBEDDING_MODEL = "text-embedding-ada-002"

# Input size limit (to prevent excessive resource consumption)
MAX_INPUT_LENGTH = 8192  # Matches Ada's context window

def generate_salt():
    """Generates a random salt for hashing."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters

def hash_input(text, salt):
    """Hashes the input text with a salt to prevent reverse engineering."""
    salted_text = salt + text
    hashed_text = hashlib.sha256(salted_text.encode('utf-8')).hexdigest()
    return hashed_text

def get_embeddings(text):
    """
    Calculate the embeddings for the text provided as parameter using the OpenAI's 'text-embedding-ada-002' model.
    Then, return a list of the embeddings.
    """
    if not openai.api_key:
        logging.error("OpenAI API key not found. Please set the OPENAI_API_KEY environment variable.")
        raise ValueError("OpenAI API key not found. Please set the OPENAI_API_KEY environment variable.")

    if not isinstance(text, str):
        logging.error(f"Invalid input type: {type(text)}. Expected a string.")
        raise TypeError("Input must be a string.")

    if len(text) > MAX_INPUT_LENGTH:
        logging.warning(f"Input text exceeds maximum length ({MAX_INPUT_LENGTH} characters). Truncating.")
        text = text[:MAX_INPUT_LENGTH]

    try:
        # Input sanitization (basic example - remove control characters)
        text = ''.join(ch for ch in text if ch.isprintable())

        # Hashing the input (for audit logging or security purposes)
        salt = generate_salt()
        hashed_input = hash_input(text, salt)
        logging.info(f"Input hashed (SHA256): {hashed_input[:20]}... (Salt: {salt[:8]}...)") # Log only a portion of the hash and salt

        response = openai.Embedding.create(
            input=[text],  # Wrap in a list as required by the API
            model=EMBEDDING_MODEL
        )

        embeddings = response['data'][0]['embedding']
        return embeddings

    except openai.error.OpenAIError as e:
        logging.error(f"OpenAI API error: {e}")
        raise  # Re-raise the exception to be handled upstream

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise  # Re-raise the exception to be handled upstream

if __name__ == '__main__':
    try:
        text_to_embed = "This is a sample text for embedding."
        embeddings = get_embeddings(text_to_embed)
        print(f"Embeddings: {embeddings[:10]}...") # Print only the first 10 elements for brevity
    except Exception as e:
        print(f"Error: {e}")

