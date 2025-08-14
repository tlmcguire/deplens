state_variable: public(uint256)
lock: public(bool)

@public
def __init__():
    self.state_variable = 0
    self.lock = False

@public
def vulnerable_function():
    assert not self.lock, "Reentrant call detected!"
    self.lock = True


    self.state_variable += 1

    self.lock = False

@public
def another_function():
    assert not self.lock, "Reentrant call detected!"
    self.lock = True

    self.state_variable -= 1

    self.lock = False