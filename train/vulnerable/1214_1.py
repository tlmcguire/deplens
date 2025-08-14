
@public
@constant
def create_from_blueprint(raw_args: bool, args: list) -> address:
    if raw_args:
        return _build_create_IR(args)

def _build_create_IR(args: list) -> address:
    return create_new_contract(args)

args_with_side_effects = [some_function_that_changes_state(), another_value]
create_from_blueprint(True, args_with_side_effects)