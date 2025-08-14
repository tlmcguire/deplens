@public
def safe_function(value: uint256):
    cached_value: uint256 = value
    raw_call(msg.sender, msg.data, gas=0, outsize=0)