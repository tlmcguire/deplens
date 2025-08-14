import rclpy
from rclpy.node import Node
from std_msgs.msg import String

class VulnerableNode(Node):
    def __init__(self):
        super().__init__('vulnerable_node')
        self.publisher_ = self.create_publisher(String, 'unsafe_topic', 10)
        self.subscription = self.create_subscription(
            String,
            'unsafe_topic',
            self.listener_callback,
            10)
        self.subscription

    def listener_callback(self, msg):
        self.get_logger().info(f'Received: "{msg.data}"')
        self.process_message(msg.data)

    def process_message(self, message):
        while True:
            self.get_logger().info(f'Processing: "{message}"')

def main(args=None):
    rclpy.init(args=args)
    vulnerable_node = VulnerableNode()
    rclpy.spin(vulnerable_node)
    vulnerable_node.destroy_node()
    rclpy.shutdown()

if __name__ == '__main__':
    main()