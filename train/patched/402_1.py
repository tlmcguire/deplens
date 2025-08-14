
def vulnerable_function(a, b):
    global side_effect_var
    side_effect_var = a + 1
    return uint256_addmod(a, b, 10)

def fixed_function(a, b):
    temp_a = a + 1
    return uint256_addmod(temp_a, b, 10)