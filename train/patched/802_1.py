def receive_room_key(self, room_key):
    if not self.is_valid_sender(room_key.sender):
        raise ValueError("Invalid sender for room key")

    self.store_room_key(room_key)

def is_valid_sender(self, sender):
    return sender in self.trusted_senders