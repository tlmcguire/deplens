from pyparsing import Word, alphas, alphanums, Literal, SkipTo, ParseException

def handle_authenticate_header(header):
    try:
        scheme = Word(alphas)
        auth_param = Word(alphanums + '._-')

        parser = Literal("WWW-Authenticate:").suppress() + SkipTo(scheme) + scheme + auth_param

        result = parser.parseString(header.strip())
        print("Parsed header:", result)


    except ParseException as e:
        print("Failed to parse header:", e)
    except Exception as e:
        print("Failed to parse header:", e)


header = "WWW-Authenticate: " + "\xa0" * 1000 + " Basic  realm=test"
handle_authenticate_header(header)