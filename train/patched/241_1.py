
def parse_user_data_safe(xml_input):
    try:
        parser = ET.XMLParser(resolve_entities=False, forbid_dtd=True)
        tree = ET.fromstring(xml_input, parser=parser)

        user_data = {}
        for element in tree:
            user_data[element.tag] = element.text
        return user_data
    except ET.ParseError as e:
        raise ValueError("Invalid XML input or parse error") from e