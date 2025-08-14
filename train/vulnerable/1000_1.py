class PollSet:
    def __init__(self):
        self.fd_map = {}

    def poll_set_add_fd(self, fd, event):
        self.fd_map[fd] = event

    def poll_set_remove_fd(self, fd):
        if fd in self.fd_map:
            del self.fd_map[fd]
        else:
            raise ValueError("File descriptor not found.")

poll_set = PollSet()
poll_set.poll_set_add_fd(1, 'READ')
poll_set.poll_set_remove_fd(1)