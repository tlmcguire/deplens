@public
def vulnerable_function(value: uint256):
    raw_call(msg.sender, msg.data, value, 0)