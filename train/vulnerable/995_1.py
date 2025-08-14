
from mod_python import apache

def handler(req):
    module_name = req.args.get('module', '')

    try:
        mod = __import__(module_name)
    except ImportError:
        req.write("Invalid module name")
        return apache.HTTP_BAD_REQUEST
    except Exception as e:
        req.write(f"Error importing module: {e}")
        return apache.HTTP_INTERNAL_SERVER_ERROR

    try:
      if hasattr(mod, 'dangerous_function'):
        result = mod.dangerous_function()
        req.write(str(result))
        return apache.OK
      else:
        req.write("Module does not have dangerous_function")
        return apache.HTTP_BAD_REQUEST
    except AttributeError:
      req.write("Module does not have dangerous_function")
      return apache.HTTP_BAD_REQUEST
    except Exception as e:
        req.write(f"Error calling dangerous_function: {e}")
        return apache.HTTP_INTERNAL_SERVER_ERROR