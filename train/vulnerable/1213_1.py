
msg_data = b"example_data"

@public
def vulnerable_function(start: uint256, length: uint256):
    return msg_data[start:start + length]

@public
def side_effect_function() -> uint256:
    return 1

@public
def exploit_function():
    return vulnerable_function(side_effect_function(), side_effect_function())