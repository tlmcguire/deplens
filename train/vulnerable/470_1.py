import sys

def handle_core_dump(module_name):
    try:
        __import__(module_name)
    except ImportError as e:
        print(f"Error importing module: {e}")

user_input = sys.argv[1]
handle_core_dump(user_input)