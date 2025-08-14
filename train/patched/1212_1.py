
class RawLog:
    def build_IR(self, topics):
        unwrapped_topics = [self.unwrap_topic(topic) for topic in topics]
        self.log(unwrapped_topics)

    def unwrap_topic(self, topic):
        return topic

    def log(self, topics):
        print("Logging topics:", topics)

raw_log = RawLog()
raw_log.build_IR(['0x123', '0x456'])