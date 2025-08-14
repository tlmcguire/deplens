
@public
@payable
def vulnerable_function(target: address):
    raw_call(target, b'', value=msg.value)

@public
@payable
def safe_function(target: address):
    assert msg.value == 0, "Value cannot be sent with delegatecall/staticcall"
    raw_call(target, b'')