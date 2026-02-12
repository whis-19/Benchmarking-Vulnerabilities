import logging

     class SafeLogFilter(logging.Filter):
         def filter(self, record):
             record.msg = str(record.msg).replace('%', '%%').replace('\n', '').replace('\r', '')
             if record.args:
                 record.args = tuple(str(arg).replace('%', '%%').replace('\n', '').replace('\r', '') for arg in record.args)
             return True

     logger = logging.getLogger()
     logger.setLevel(logging.DEBUG)
     handler = logging.StreamHandler()
     formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
     handler.setFormatter(formatter)
     handler.addFilter(SafeLogFilter())
     logger.addHandler(handler)

     @app.route('/')
     def main():
         try:
             user_input = request.args.get('input')
             logger.error("Error occurred with user input: %s", user_input)
             error = f"An error occurred"
         except Exception as e:
             logger.exception("Error in main route")
             error = f"An error occurred: {str(e)}"

