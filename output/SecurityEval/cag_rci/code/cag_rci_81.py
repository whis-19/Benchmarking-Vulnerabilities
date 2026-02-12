# Example JSON Schema with more specific validation rules
TOKEN_SCHEMA = {
    "type": "object",
    "properties": {
        "user_id": {"type": ["integer", "string"]},  # Allow both integer and string
        "username": {"type": "string", "minLength": 3, "maxLength": 50},  # Example length constraints
        "expiration": {"type": "number"},
        "domain": {"type": "string", "enum": ALLOWED_DOMAINS}, # Validate against allowed domains
        "timestamp": {"type": "number"},
        "jti": {"type": "string", "pattern": "^[a-zA-Z0-9-]+$"}  # Example pattern for JTI
    },
    "required": ["user_id", "username", "expiration", "domain", "timestamp", "jti"],
    "additionalProperties": False  # Reject unexpected fields
}

