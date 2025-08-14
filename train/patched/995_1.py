
from mod_python import apache

ALLOWED_MODULES = {'safe_module': None}

def handler(req):
    module_name = req.args.get('module', '')

    if module_name not in ALLOWED_MODULES:
        req.write("Access denied to module: {}".format(module_name))
        return apache.HTTP_FORBIDDEN

    try:
        mod = __import__(module_name)
        result = mod.safe_function()
        req.write(str(result))
        return apache.OK
    except Exception as e:
         req.write("Error accessing module: {}".format(e))
         return apache.HTTP_INTERNAL_SERVER_ERROR