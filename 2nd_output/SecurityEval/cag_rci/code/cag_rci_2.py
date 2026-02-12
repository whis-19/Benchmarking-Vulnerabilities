# Schema Validation Example (with comment)
def parse_xml(xml_string, source="unknown", schema_file=None):
    '''
    Parse xml_string and return the root element of the XML document.
    Uses defusedxml to prevent XML vulnerabilities.
    Optionally validates against a schema.
    '''

    try:
        root = fromstring(xml_string)  # Use defusedxml's fromstring

        if schema_file:
            # IMPORTANT: Parse with defusedxml *before* schema validation.
            # Loading the schema itself can be vulnerable to XXE if the schema file is untrusted.
            # defusedxml protects against this during the initial parsing of the XML data.
            try:
                xml_schema = etree.XMLSchema(file=schema_file)
                xml_schema.assertValid(root)
            except etree.XMLSchemaError as e:
                logging.error(f"Schema Error from source {source}: {e}")
                return None
            except etree.XMLSchemaValidateError as e:
                logging.error(f"Validation Error from source {source}: {e}")
                return None

        return root
    except DET.ParseError as e:  # Use DET.ParseError
        logging.error(f"XML Parsing Error (defusedxml) from source {source}: {e}")
        return None
    except ET.ParseError as e: #Catch standard ET parsing errors too
        logging.error(f"XML Parsing Error (standard) from source {source}: {e}")
        return None
    except ValueError as e:
        logging.error(f"Invalid data type in XML from source {source}: {e}")
        return None
    except TypeError as e: # Example of another specific exception
        logging.error(f"Type error during XML processing from source {source}: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred from source {source}: {e}") # Log the full traceback
        return None

# Error Message Sanitization Example
def parse_xml(xml_string, source="unknown", schema_file=None):
    try:
        # ... (parsing logic) ...
    except Exception as e:
        # Sanitize the error message before logging
        error_message = str(e)
        # Example: Redact credit card numbers
        error_message = re.sub(r"\b\d{13,19}\b", "REDACTED_CREDIT_CARD", error_message)
        # Example: Truncate long strings
        if len(error_message) > 500:
            error_message = error_message[:500] + "..."
        logging.exception(f"An unexpected error occurred from source {source}: {error_message}")
        return None

