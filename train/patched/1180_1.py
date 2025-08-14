class CompletionQueue:
    def __init__(self):
        self.dbg = "debug_info"

    def debug_cq_remove(self):
        print("Removing debug information.")
        self.dbg = None

    def destroy_cq(self):
        success = False
        if not success:
            print("Failed to destroy CQ. Proceeding to cleanup.")
            self.debug_cq_remove()
        else:
            print("Successfully destroyed CQ.")

cq = CompletionQueue()
cq.destroy_cq()