from lxml import etree
import os

# ... (getXmlRoot function from above) ...

if __name__ == "__main__":
    root = getXmlRoot()
    if root is not None:
        # Process the XML data
        for element in root.iter():
            print(f"Element tag: {element.tag}, text: {element.text}")
    else:
        print("Failed to parse XML.")

