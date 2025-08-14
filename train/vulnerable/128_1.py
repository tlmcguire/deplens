import xml.parsers.expat

parser = xml.parsers.expat.ParserCreate()

def start_element(name, attrs):
    print("Start element:", name, attrs)

def end_element(name):
    print("End element:", name)

def char_data(data):
    print("Character data:", repr(data))

parser.StartElementHandler = start_element
parser.EndElementHandler = end_element
parser.CharacterDataHandler = char_data

with open("example.xml", "rb") as f:
    parser.ParseFile(f)