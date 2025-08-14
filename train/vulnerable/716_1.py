import tensorflow as tf

def vulnerable_poisson_loss(y_true, y_pred):
    return tf.keras.losses.poisson(y_true, y_pred)

y_true = tf.random.uniform((100000, 100000), minval=0, maxval=10)
y_pred = tf.random.uniform((100000, 100000), minval=0, maxval=10)

try:
    loss = vulnerable_poisson_loss(y_true, y_pred)
    print("Loss:", loss.numpy())
except Exception as e:
    print("Error:", e)