
def vulnerable_function(a, b):
    global side_effect_var
    side_effect_var = a + 1
    return uint256_addmod(a, side_effect_var, 10)