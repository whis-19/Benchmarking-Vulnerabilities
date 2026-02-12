from markupsafe import escape

   # ... inside the upload_file function ...
   return f'File uploaded successfully to <a href="{url_for("download_file", name=unique_filename)}">{escape(unique_filename)}</a>'

