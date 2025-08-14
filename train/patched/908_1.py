import tensorflow as tf

def safe_draw_bounding_boxes(boxes, image, colors):
    if boxes.shape[-1] != 4:
        raise ValueError("The last dimension of boxes must be 4.")

    return tf.raw_ops.DrawBoundingBoxesV2(boxes=boxes, image=image, colors=colors)

boxes = tf.constant([[0.1, 0.2, 0.5, 0.5], [0.3, 0.3, 0.6, 0.6]], dtype=tf.float32)
image = tf.zeros([100, 100, 3], dtype=tf.float32)
colors = tf.constant([[1.0, 0.0, 0.0]], dtype=tf.float32)

output_image = safe_draw_bounding_boxes(boxes, image, colors)