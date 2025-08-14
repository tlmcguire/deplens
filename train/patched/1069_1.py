import json
import os

def safe_postprocess(user_input):
    try:
        parsed_json = json.loads(user_input)

        if isinstance(parsed_json, dict):
            for key in parsed_json.keys():
              if not isinstance(key, str):
                raise ValueError("Invalid key type in JSON input.")
              if "path" in key.lower():
                raise ValueError("Input contains a disallowed 'path' key.")

            for value in parsed_json.values():
              if isinstance(value, str):
                if ".." in value or "/" in value:
                  raise ValueError("Input contains disallowed characters in value.")


    except json.JSONDecodeError:
        raise ValueError("Invalid JSON input.")