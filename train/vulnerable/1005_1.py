
owner: public(address)
data: public(uint256)

@public
def set_data(new_data: uint256):
    self.data = new_data

@public
def set_owner(new_owner: address):
    self.owner = new_owner