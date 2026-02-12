import jwt
import os
import jsonschema  # For payload validation (optional)
import json
import configparser  # For reading configuration files
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def load_config(config_file="config.ini"):
    """Loads configuration from a file."""
    config = configparser.ConfigParser()
    config.read(config_file)
    return config

def get_secret(config, secrets_manager="env"):
    """Retrieves the JWT secret from the specified secrets manager."""
    if secrets_manager == "env":
        secret = os.environ.get("JWT_SECRET")
        if secret is None:
            raise ValueError("JWT_SECRET environment variable not set.")
        return secret
    elif secrets_manager == "vault":
        # Implement retrieval from HashiCorp Vault
        # (Requires vault library and proper authentication)
        logging.warning("Vault integration not implemented yet.") # Log the unimplemented feature
        raise NotImplementedError("Vault integration not implemented yet.")
    elif secrets_manager == "aws":
        # Implement retrieval from AWS Secrets Manager
        # (Requires boto3 library and proper IAM permissions)
        logging.warning("AWS Secrets Manager integration not implemented yet.") # Log the unimplemented feature
        raise NotImplementedError("AWS Secrets Manager integration not implemented yet.")
    else:
        raise ValueError(f"Unsupported secrets manager: {secrets_manager}")


def load_allowed_algorithms(config):
    """Loads the allowed algorithms from the configuration."""
    try:
        algorithms_str = config.get("jwt", "allowed_algorithms")
        return [alg.strip() for alg in algorithms_str.split(",")]
    except (configparser.NoSectionError, configparser.NoOptionError):
        logging.warning("Allowed algorithms not found in config, using default HS256")
        return ["HS256"]  # Default algorithm


def load_payload_schema(schema_file="payload_schema.json"):
    """Loads the JSON schema from a file."""
    try:
        with open(schema_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning(f"Schema file not found: {schema_file}, skipping validation")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON schema: {e}, skipping validation")
        return None


def jwt_decode(token, secret=None, algorithms=None):
    '''
    Decode a JSON Web Token.

    :param token: The JWT token to decode.
    :param secret: The secret key used to sign the token. If None, attempts to use a secrets manager.
    :param algorithms: A list of allowed algorithms for decoding.  Defaults to loading from config.
    :return: The decoded payload as a dictionary, or None if decoding fails.
    :raises jwt.exceptions.InvalidTokenError: If the token is invalid (e.g., expired, invalid signature).
    :raises ValueError: If the secret is not provided and the secrets manager is not configured.
    '''
    config = load_config()

    if secret is None:
        try:
            secret = get_secret(config, config.get("jwt", "secrets_manager", fallback="env"))
        except (configparser.NoSectionError, configparser.NoOptionError) as e:
            logging.error(f"Error reading secrets manager config: {e}")
            raise ValueError("Secrets manager not configured.") from e

    if algorithms is None:
        algorithms = load_allowed_algorithms(config)

    try:
        decoded_payload = jwt.decode(token, secret, algorithms=algorithms)
        return decoded_payload
    except jwt.exceptions.InvalidTokenError as e:
        logging.error(f"Error decoding JWT: {e}")  # Log the error for debugging
        return None
    except Exception as e:
        logging.exception(f"Unexpected error decoding JWT: {e}")  # Log unexpected errors
        return None


def generate_jwt(payload, secret=None, algorithm="HS256", allowed_algorithms=None):
    '''
    Generates a JSON Web Token (JWT) from a payload.

    :param payload: The payload to encode into the JWT.  Must be a dictionary.
    :param secret: The secret key used to sign the token. If None, attempts to use a secrets manager.
    :param algorithm: The algorithm to use for signing. Defaults to HS256.
    :param allowed_algorithms: List of allowed algorithms. Defaults to loading from config.
    :return: The encoded JWT as a string.
    :raises ValueError: If the secret is not provided and the secrets manager is not configured, or if the algorithm is not allowed.
    :raises TypeError: If the payload is not a dictionary.
    :raises jsonschema.ValidationError: If the payload does not conform to the defined schema (if validation is enabled).
    '''
    config = load_config()

    if secret is None:
        try:
            secret = get_secret(config, config.get("jwt", "secrets_manager", fallback="env"))
        except (configparser.NoSectionError, configparser.NoOptionError) as e:
            logging.error(f"Error reading secrets manager config: {e}")
            raise ValueError("Secrets manager not configured.") from e

    if allowed_algorithms is None:
        allowed_algorithms = load_allowed_algorithms(config)

    if algorithm not in allowed_algorithms:
        raise ValueError(f"Algorithm '{algorithm}' is not allowed. Allowed algorithms: {allowed_algorithms}")

    if not isinstance(payload, dict):
        raise TypeError("Payload must be a dictionary.")

    # Payload validation (optional)
    schema = load_payload_schema()
    if schema:
        try:
            jsonschema.validate(payload, schema)
        except jsonschema.ValidationError as e:
            raise ValueError(f"Invalid payload: {e}")

    try:
        encoded_jwt = jwt.encode(payload, secret, algorithm=algorithm)
        return encoded_jwt
    except jwt.exceptions.JWTError as e:
        logging.error(f"Error encoding JWT: {e}")
        return None


# Example Usage (for demonstration - replace with your actual usage)
if __name__ == '__main__':
    # WARNING: Setting JWT_SECRET in code is ONLY for local testing!
    # NEVER do this in production. Use a proper secrets management system.
    config = load_config()
    if config.get("jwt", "secrets_manager", fallback="env") == "env":
        os.environ["JWT_SECRET"] = "your-super-secret-key"  # Replace with a strong, random key

    # Example payload
    payload = {
        "user_id": 123,
        "username": "testuser",
        "exp": 1678886400,  # Example expiration timestamp (March 15, 2023)
        "aud": "my-application",  # Example audience
        "iss": "my-issuer"  # Example issuer
    }

    # Generate a JWT
    try:
        jwt_token = generate_jwt(payload)
        print(f"Generated JWT: {jwt_token}")

        # Decode the JWT
        decoded_payload = jwt_decode(jwt_token)
        if decoded_payload:
            print(f"Decoded Payload: {decoded_payload}")
        else:
            print("JWT decoding failed.")

    except ValueError as e:
        print(f"Error: {e}")
    except TypeError as e:
        print(f"Type Error: {e}")
    except Exception as e:
        logging.exception("An unexpected error occurred:")

