"""Tests for tensorflow.python.framework.constant_op."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import parameterized

from tensorflow.python.framework import constant_op
from tensorflow.python.framework import dtypes
from tensorflow.python.framework import ops
from tensorflow.python.platform import test


class ConstantOpTest(test.TestCase, parameterized.TestCase):

  @parameterized.parameters(
      dtypes.bfloat16,
      dtypes.complex128,
      dtypes.complex64,
      dtypes.double,
      dtypes.float16,
      dtypes.float32,
      dtypes.float64,
      dtypes.half,
      dtypes.int16,
      dtypes.int32,
      dtypes.int64,
      dtypes.int8,
      dtypes.qint16,
      dtypes.qint32,
      dtypes.qint8,
      dtypes.quint16,
      dtypes.quint8,
      dtypes.uint16,
      dtypes.uint32,
      dtypes.uint64,
      dtypes.uint8,
  )
  def test_convert_string_to_number(self, dtype):
    with self.assertRaises(TypeError):
      constant_op.constant("hello", dtype)


if __name__ == "__main__":
  ops.enable_eager_execution()
  test.main()
