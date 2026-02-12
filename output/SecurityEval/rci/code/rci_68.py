import tempfile
import os
import uuid
import logging
import json

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.ERROR, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')


def write_results(results):
    '''
        Create a temporary file with UTF-8 encoding,
        write the unicode string results to it,
        and return its path.  Uses tempfile.TemporaryFile for safer deletion.
    '''
    try:
        # Create a temporary file with a unique name and UTF-8 encoding.
        # The file will be automatically deleted when closed.
        with tempfile.TemporaryFile(
            mode='w+t',  # Read and write text mode
            encoding='utf-8',
            prefix='results_' + str(uuid.uuid4())[:8] + '_',
            suffix='_' + str(uuid.uuid4())[:8] + '.txt',  # More random suffix
            delete=True  # Ensure automatic deletion
        ) as temp_file:

            # Write the results to the temporary file.
            if isinstance(results, str):
                temp_file.write(results)
            else:
                try:
                    json_string = json.dumps(results)
                    temp_file.write(json_string)
                except TypeError as e:
                    logging.error(f"Could not serialize results to JSON: {e}", exc_info=True)
                    return None


            # Flush the buffer to ensure data is written to disk.
            temp_file.flush()
            temp_file.seek(0) # Rewind to the beginning to read

            content = temp_file.read() # Read the content

            return content # Return the content instead of the file path

    except Exception as e:
        logging.error(f"Error writing results to temporary file: {e}", exc_info=True)  # Log the exception
        return None


# Example usage (for testing):
if __name__ == '__main__':
    results_data = "This is a test string with unicode characters: こんにちは世界"
    content = write_results(results_data)

    if content:
        print(f"Results: {content}")
    else:
        print("Failed to write results.")

    results_data_json = {"key1": "value1", "key2": 123}
    content_json = write_results(results_data_json)

    if content_json:
        print(f"JSON Results: {content_json}")
    else:
        print("Failed to write JSON results.")

