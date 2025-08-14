class RawLog:
    def build_IR(self, topics):
        logged_topics = topics
        self.log(logged_topics)

    def log(self, topics):
        print("Logging topics:", topics)

raw_log = RawLog()
raw_log.build_IR(['0x123', '0x456'])