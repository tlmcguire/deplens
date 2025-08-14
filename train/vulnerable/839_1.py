import tensorflow as tf



def vulnerable_sdca_optimizer(learning_rate, num_iterations):
    optimizer = tf.raw_ops.SdcaOptimizer(
        learning_rate=learning_rate,
        num_iterations=num_iterations,
        dual_coefficients=None,
        primal_loss=None,
    )
    return optimizer

result = vulnerable_sdca_optimizer(0.01, 100)