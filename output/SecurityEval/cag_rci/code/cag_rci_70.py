#    import magic
#    import logging # Import logging module

#    def validate_file_type(file_path, allowed_mime_types):
#        try:
#            mime = magic.from_file(file_path, mime=True).decode('utf-8')
#            return mime in allowed_mime_types
#        except Exception as e:
#            logging.error(f"Error determining file type for {file_path}: {e}")
#            return False
#

