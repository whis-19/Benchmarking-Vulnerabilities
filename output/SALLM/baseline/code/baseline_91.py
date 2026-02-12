parser = etree.XMLParser(resolve_entities=False)
xml_tree = etree.parse(StringIO(xml_data), parser)

