from google.protobuf import message as protobuf

class MyMessage(protobuf.Message):
    key = protobuf.Field(protobuf.STRING, number=1)
    value = protobuf.Field(protobuf.STRING, number=2)

def process_message_set(message_set):
    for message in message_set:
        print(f"Key: {message.key}, Value: {message.value}")

crafted_message = [
    MyMessage(key="key1", value="value1"),
    MyMessage(key="key2", value="value2"),
]

process_message_set(crafted_message)