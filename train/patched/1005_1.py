owner: public(address)
data: public(uint256)

@public
def set_data(new_data: uint256):
    assert new_data >= 0
    self.data = new_data

@public
def set_owner(new_owner: address):
    assert new_owner != ZERO_ADDRESS
    self.owner = new_owner
