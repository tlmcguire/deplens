import difflib
def compare_lines(line1, line2):
    return difflib.IS_LINE_JUNK(line1) or difflib.IS_LINE_JUNK(line2)
compare_lines('a' * 50000, 'b' * 50000)