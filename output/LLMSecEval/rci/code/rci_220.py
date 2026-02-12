def validate_pdf(file_storage):
    """Validates if the file is a valid PDF and doesn't contain suspicious content."""
    try:
        from PyPDF2 import PdfReader
        from PyPDF2.generic import NameObject, IndirectObject

        pdf = PdfReader(BytesIO(file_storage.read()))
        # Reset the file pointer
        file_storage.seek(0)

        # Check for JavaScript (more comprehensive)
        for page in pdf.pages:
            if "/JS" in page.get_text():
                print("PDF contains JavaScript (suspicious)")
                return False
            if "/JavaScript" in page.get_text():
                print("PDF contains JavaScript (suspicious)")
                return False

        # Check for OpenAction (JavaScript execution on open)
        if pdf.trailer["/Root"].get("/OpenAction"):
            print("PDF contains OpenAction (suspicious)")
            return False

        # Check for embedded files (potential for malicious executables)
        if "/EmbeddedFiles" in pdf.trailer["/Root"]:
            print("PDF contains embedded files (suspicious)")
            return False

        # Check for external links (potential phishing)
        for page in pdf.pages:
            try:
                for annot in page["/Annots"]:
                    obj = annot.get_object()
                    if isinstance(obj, IndirectObject):
                        obj = obj.get_object()
                    if obj.get("/Subtype") == "/Link" and obj.get("/A") and obj["/A"].get("/URI"):
                        print(f"PDF contains external link: {obj['/A']['/URI']}")
                        return False # Or log and continue, depending on your policy
            except Exception as e:
                print(f"Error checking annotations: {e}")

        return True
    except Exception as e:
        print(f"PDF validation failed: {e}")
        return False

