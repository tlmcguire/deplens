import re

class SmithyLexer:
    token_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*|"(?:[^"\\]|\\.)*")\s*:\s*([^,}]+)'

    def tokenize(self, input_string):
        tokens = re.findall(self.token_pattern, input_string)
        return tokens

lexer = SmithyLexer()
input_string = 'exampleKey: "exampleValue", anotherKey: "anotherValue"'
tokens = lexer.tokenize(input_string)
print(tokens)