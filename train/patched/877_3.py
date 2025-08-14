
from AccessControl.Implementation import setImplementation
from AccessControl.safe_formatter import safe_format
from AccessControl.safe_formatter import safe_format_map
from AccessControl.SecurityInfo import ACCESS_NONE
from AccessControl.SecurityInfo import ACCESS_PRIVATE
from AccessControl.SecurityInfo import ACCESS_PUBLIC
from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.SecurityInfo import ModuleSecurityInfo
from AccessControl.SecurityInfo import allow_class
from AccessControl.SecurityInfo import allow_module
from AccessControl.SecurityInfo import secureModule
from AccessControl.SecurityManagement import getSecurityManager
from AccessControl.SecurityManagement import setSecurityPolicy
from AccessControl.SimpleObjectPolicies import allow_type
from AccessControl.unauthorized import Unauthorized
from AccessControl.ZopeGuards import full_write_guard
from AccessControl.ZopeGuards import get_safe_globals
from AccessControl.ZopeGuards import safe_builtins


ModuleSecurityInfo('AccessControl').declarePublic('getSecurityManager')


for name in ('string', 'math', 'random', 'sets'):
    ModuleSecurityInfo(name).setDefaultAccess('allow')

ModuleSecurityInfo('DateTime').declarePublic('DateTime')

rules = {m: True for m in dir(str) if not m.startswith('_')}
rules['format'] = safe_format
rules['format_map'] = safe_format_map
allow_type(str, rules)

zodbupdate_decode_dict = {
    'AccessControl.users User name': 'utf-8',
    'AccessControl.users User __': 'utf-8',
}
