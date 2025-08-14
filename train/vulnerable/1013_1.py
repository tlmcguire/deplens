import rclpy
from rclpy.node import Node

class VulnerableNode(Node):
    def __init__(self):
        super().__init__('vulnerable_node')

    def create_node(self, node_name):
        return rclpy.create_node(node_name)

def main(args=None):
    rclpy.init(args=args)
    vulnerable_node = VulnerableNode()

    new_node = vulnerable_node.create_node('malicious_node')

    rclpy.spin(vulnerable_node)
    vulnerable_node.destroy_node()
    rclpy.shutdown()

if __name__ == '__main__':
    main()