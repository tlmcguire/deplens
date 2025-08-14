
@public
@constant
def create_from_blueprint(raw_args: bool, args: list) -> address:
    if raw_args:
        return _build_create_IR(args)

def _build_create_IR(args: list) -> address:
    return create_new_contract(args)

@public
@constant
def create_from_blueprint_fixed(raw_args: bool, args: list) -> address:
    if raw_args:
        cached_args = args
        return _build_create_IR_fixed(cached_args)

def _build_create_IR_fixed(cached_args: list) -> address:
    return create_new_contract(cached_args)