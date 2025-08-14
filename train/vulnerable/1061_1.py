@public
@payable
def vulnerable_function(target: address):
    raw_call(target, b'', value=msg.value)