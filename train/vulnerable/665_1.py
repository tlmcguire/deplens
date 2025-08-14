import os

def load_module(module_name):
    module_path = os.path.join('/tmp', module_name)
    if os.path.isfile(module_path):
        exec(open(module_path).read(), globals())
    else:
        raise ImportError(f"Module {module_name} not found in /tmp.")

if __name__ == "__main__":
    try:
        load_module('deployUtil.py')
        load_module('vds_bootstrap.py')
    except ImportError as e:
        print(e)