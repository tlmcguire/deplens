"""API for defining graph functions with some additional eager semantics.

def_function.function wraps the function concept in function.py ("defun") to
allow initializing `tf.Variable`s with subgraphs of the function. For example:

```python
class M(tf.Module):
  def __init__(self):
    self.v_opinit = None
    self.v_arginit = None

  @tf.function
  def __call__(self, x):
    # Variables are only created on the first call to the function. This is a
    # common pattern in layer libraries.
    if self.v_opinit is None:
      # self.v_opinit will outlive the function call, but `tf.ones` is traced as
      # part of the function body before the `tf.Variable` object is
      # created. This subgraph is easy to lift out of the function.
      self.v_opinit = tf.Variable(tf.ones([]))

      # If arguments feed into variable initialization, it can be very tricky to
      # disentangle from the rest of the function. We don't attempt it.
      self.v_arginit = tf.Variable(tf.ones(tf.shape(x)) * tf.constant(2.))
    return self.v_opinit + self.v_arginit + x
```

These patterns with "defun" throw an error asking the user to put the variable's
initializer in a lambda. With tf.function they work with eager semantics either
by lifting the subgraph out of the function and using it to initialize the
variable, or by initializing variables on the first call to the function (if
they weren't already initialized by something else, e.g. a checkpoint API). The
latter requires tf.conds, and is not well supported by TF-XLA, so we only do it
when necessary.

Since these patterns are relatively common in layer libraries, we expose the
wrapper in this file as `tf.function`. The function concept in function.py is an
internal implementation detail.

In order to support these variable initialization patterns, tf.function defines
a variable subtype (UnliftedInitializerVariable) which collects the input
subgraph. This type of variable replaces the regular variable type on the first
tf.function trace. To exclude initializers from the function body (the `tf.ones`
ops above and associated assignment operations), tf.function traces a second
time if it sees variables on the first call.
"""

import functools
import threading
import types as types_lib
import weakref
import six

from google.protobuf import text_format as _text_format
from google.protobuf.message import DecodeError
from tensorflow.core.framework import attr_value_pb2
from tensorflow.python.distribute.parallel_device import parallel_device
from tensorflow.python.eager import context
from tensorflow.python.eager import function as function_lib
from tensorflow.python.eager import lift_to_graph
from tensorflow.python.eager import monitoring
from tensorflow.python.framework import composite_tensor
from tensorflow.python.framework import errors
from tensorflow.python.framework import func_graph as func_graph_module
from tensorflow.python.framework import ops
from tensorflow.python.ops import array_ops
from tensorflow.python.ops import control_flow_ops
from tensorflow.python.ops import control_flow_util
from tensorflow.python.ops import math_ops
from tensorflow.python.ops import random_ops
from tensorflow.python.ops import resource_variable_ops
from tensorflow.python.platform import tf_logging as logging
from tensorflow.python.profiler import trace
from tensorflow.python.training.tracking import base as trackable
from tensorflow.python.types import core
from tensorflow.python.util import deprecation
from tensorflow.python.util import nest
from tensorflow.python.util import object_identity
from tensorflow.python.util import tf_decorator
from tensorflow.python.util import traceback_utils
from tensorflow.python.util.tf_export import tf_export

FREQUENT_TRACING_WARNING_MAX_CALL_HISTORY = 10
FREQUENT_TRACING_WARNING_THRESHOLD = 5
FREQUENT_TRACING_WARNING_MAX_WARNING_PER_DETECTOR = 2
ALLOW_DYNAMIC_VARIABLE_CREATION = False

_tf_function_counter = monitoring.Counter(
    "/tensorflow/core/tf_function_counter",
    "Counter for the number of tf.functions created when Eager execution is "
    "enabled.",
    "jit_compile")


class _FrequentTracingDetector(object):
  """Class keeping track of how many recent calls triggered tracing."""

  __slots__ = ["_calls_per_tracings", "_call_count", "_total_warning_count"]

  def __init__(self):
    self._calls_per_tracings = []
    self._total_warning_count = 0
    self._call_count = 0

  def called_with_tracing(self, function_name, omit_warning):
    """Updates the list of most recent calls' tracing information.

    Warns the user when recent calls caused retracing too often.

    Args:
      function_name: the python function being traced.
      omit_warning: If 'True', this call will not warn the user even if
        retracing happens too often.
    """
    self._call_count += 1
    self._calls_per_tracings.append(1)

    while self._calls_per_tracings:
      if (self._call_count - self._calls_per_tracings[0] >
          FREQUENT_TRACING_WARNING_MAX_CALL_HISTORY):
        self._call_count -= self._calls_per_tracings.pop(0)
      else:
        break

    if (omit_warning or self._total_warning_count >=
        FREQUENT_TRACING_WARNING_MAX_WARNING_PER_DETECTOR):
      return
    if len(self._calls_per_tracings) >= FREQUENT_TRACING_WARNING_THRESHOLD:
      self._total_warning_count += 1
      logging.warning(
          "{} out of the last {} calls to {} triggered tf.function "
          "retracing. Tracing is expensive and the excessive number of "
          "tracings could be due to (1) creating @tf.function repeatedly in "
          "a loop, (2) passing tensors with different shapes, (3) passing "
          "Python objects instead of tensors. For (1), please define your "
          "@tf.function outside of the loop. For (2), @tf.function has "
          "experimental_relax_shapes=True option that relaxes argument "
          "shapes that can avoid unnecessary retracing. For (3), please "
          "refer to "
          "https://www.tensorflow.org/guide/function#controlling_retracing"
          " and https://www.tensorflow.org/api_docs/python/tf/function for "
          " more details.".format(
              len(self._calls_per_tracings), self._call_count, function_name))

  def called_without_tracing(self):
    if not self._calls_per_tracings:
      self._calls_per_tracings = [0]
    self._calls_per_tracings[-1] += 1
    self._call_count += 1


class _FrequentTracingDetectorManager(object):
  """Class for the management of all _FrequentTracingDetector objects."""

  __slots__ = ["_detectors", "_lock"]

  def __init__(self):
    self._detectors = weakref.WeakKeyDictionary()
    self._lock = threading.Lock()

  def _get_detector(self, key):
    if key not in self._detectors:
      self._detectors[key] = _FrequentTracingDetector()
    return self._detectors[key]

  def called_without_tracing(self, key):
    with self._lock:
      detector = self._get_detector(key)
      detector.called_without_tracing()

  def called_with_tracing(self, key, function_name, omit_warning):
    with self._lock:
      detector = self._get_detector(key)
      detector.called_with_tracing(function_name, omit_warning)


_frequent_tracing_detector_manager = _FrequentTracingDetectorManager()


class UnliftedInitializerVariable(resource_variable_ops.UninitializedVariable):
  """Variable which does not lift its initializer out of function context.

  Instances of this variable, when created, build a graph which runs their
  initializer inside a tf.cond(is_initialized) block.

  This can only be created inside a defun called from (eventually) eager
  mode. That is, non-function-building graphs are not supported.
  """

  def __init__(self,
               initial_value=None,
               trainable=None,
               caching_device=None,
               name=None,
               dtype=None,
               constraint=None,
               add_initializers_to=None,
               lifted_initializer_graph=None,
               synchronization=None,
               aggregation=None,
               shape=None,
               **unused_kwargs):
    """Creates a variable.

    Args:
      initial_value: A `Tensor`, or Python object convertible to a `Tensor`,
        which is the initial value for the Variable. The initial value must have
        a shape specified unless `validate_shape` is set to False. Can also be a
        callable with no argument that returns the initial value when called.
        (Note that initializer functions from init_ops.py must first be bound
         to a shape before being used here.)
      trainable: If `True`, GradientTapes automatically watch uses of this
        Variable.
      caching_device: Optional device string or function describing where the
        Variable should be cached for reading.  Defaults to the Variable's
        device.  If not `None`, caches on another device.  Typical use is to
        cache on the device where the Ops using the Variable reside, to
        deduplicate copying through `Switch` and other conditional statements.
      name: Optional name for the variable. Defaults to `'Variable'` and gets
        uniquified automatically.
      dtype: If set, initial_value will be converted to the given type.
        If None, either the datatype will be kept (if initial_value is
       a Tensor) or float32 will be used (if it is a Python object convertible
       to a Tensor).
      constraint: An optional projection function to be applied to the variable
        after being updated by an `Optimizer` (e.g. used to implement norm
        constraints or value constraints for layer weights). The function must
        take as input the unprojected Tensor representing the value of the
        variable and return the Tensor for the projected value
        (which must have the same shape). Constraints are not safe to
        use when doing asynchronous distributed training.
      add_initializers_to: if not None and not in legacy graph mode, the
        initializer tensor will be added to this map in addition to adding the
        assignment to the function.
      lifted_initializer_graph: FuncGraph to try to lift initializers to.
      synchronization: Indicates when a distributed a variable will be
        aggregated. Accepted values are constants defined in the class
        `tf.VariableSynchronization`. By default the synchronization is set to
        `AUTO` and the current `DistributionStrategy` chooses
        when to synchronize.
      aggregation: Indicates how a distributed variable will be aggregated.
        Accepted values are constants defined in the class
        `tf.VariableAggregation`.
      shape: (optional) The shape of this variable. If None, the shape of
        `initial_value` will be used. When setting this argument to
        `tf.TensorShape(None)` (representing an unspecified shape), the variable
        can be assigned with values of different shapes.

    Raises:
      ValueError: If the initial value is not specified, or does not have a
        shape and `validate_shape` is `True`.
      RuntimeError: If called outside of a function definition.
    """
    with ops.init_scope():
      self._in_graph_mode = not context.executing_eagerly()
    if not ops.inside_function():
      resource_variable_ops.ResourceVariable.__init__(
          self, initial_value=initial_value, trainable=trainable,
          caching_device=caching_device, name=name, dtype=dtype,
          constraint=constraint)
      return
    if initial_value is None:
      raise ValueError("`initial_value` must be a Tensor or a Python "
                       "object convertible to a Tensor. Got None.")
    init_from_fn = callable(initial_value)

    if constraint is not None and not callable(constraint):
      raise ValueError(f"`constraint` with type {type(constraint)} must be a "
                       "callable.")

    with ops.name_scope(name, "Variable", []
                        if init_from_fn else [initial_value]) as scope_name:
      with ops.name_scope("Initializer"):
        if init_from_fn:
          initial_value = initial_value()
        if isinstance(initial_value, trackable.CheckpointInitialValue):
          self._maybe_initialize_trackable()
          self._update_uid = initial_value.checkpoint_position.restore_uid
          initial_value = initial_value.wrapped_value

        initial_value = ops.convert_to_tensor(initial_value,
                                              name="initial_value", dtype=dtype)
      assert initial_value is not None

      if shape is None:
        shape = initial_value.shape

    super(UnliftedInitializerVariable, self).__init__(
        trainable=trainable,
        caching_device=caching_device,
        name=name,
        shape=shape,
        dtype=initial_value.dtype,
        constraint=constraint,
        synchronization=synchronization,
        aggregation=aggregation,
        extra_handle_data=initial_value,
        **unused_kwargs)

    with ops.name_scope(scope_name):
      if self._in_graph_mode:
        with ops.init_scope():
          outer_graph = ops.get_default_graph()
        func_graph = ops.get_default_graph()
        function_placeholders = (
            func_graph.inputs + func_graph.internal_captures)
        placeholder_ops = set(
            [tensor.op for tensor in function_placeholders])
        lifted_initializer = lift_to_graph.lift_to_graph(
            [initial_value], outer_graph,
            disallowed_placeholders=placeholder_ops)[initial_value]
        with ops.init_scope():
          self._initial_value = lifted_initializer
          with ops.name_scope("IsInitialized"):
            self._is_initialized_op = (
                resource_variable_ops.var_is_initialized_op(self._handle))
          if initial_value is not None:
            with ops.name_scope("Assign") as n, ops.colocate_with(self._handle):
              self._initializer_op = resource_variable_ops.assign_variable_op(
                  self._handle, lifted_initializer, name=n)
      elif context.executing_eagerly():
        with ops.name_scope("Assign") as n, ops.colocate_with(self._handle):
          resource_variable_ops.assign_variable_op(
              self._handle, initial_value, name=n)
      else:
        if add_initializers_to is not None:
          add_initializers_to.append((self, initial_value))

        def assign_fn():
          with ops.name_scope("Assign") as n, ops.colocate_with(self._handle):
            resource_variable_ops.assign_variable_op(
                self._handle,
                initial_value,
                name=n)
          return ops.convert_to_tensor(1)
        def not_assign_fn():
          return ops.convert_to_tensor(0)
        graph = ops.get_default_graph()

        graph.capture(self._handle, shape=())
        control_flow_ops.cond(
            resource_variable_ops.var_is_initialized_op(self._handle),
            not_assign_fn, assign_fn)


RUN_FUNCTIONS_EAGERLY = False


@deprecation.deprecated(
    None,
    "Use `tf.config.run_functions_eagerly` instead of the experimental "
    "version.")
@tf_export("config.experimental_run_functions_eagerly")
def experimental_run_functions_eagerly(run_eagerly):
  """Enables / disables eager execution of `tf.function`s.

  Calling `tf.config.experimental_run_functions_eagerly(True)` will make all
  invocations of `tf.function` run eagerly instead of running as a traced graph
  function.

  See `tf.config.run_functions_eagerly` for an example.

  Note: This flag has no effect on functions passed into tf.data transformations
  as arguments. tf.data functions are never executed eagerly and are always
  executed as a compiled Tensorflow Graph.

  Args:
    run_eagerly: Boolean. Whether to run functions eagerly.
  """
  return run_functions_eagerly(run_eagerly)


@tf_export("config.run_functions_eagerly")
def run_functions_eagerly(run_eagerly):
  """Enables / disables eager execution of `tf.function`s.

  Calling `tf.config.run_functions_eagerly(True)` will make all
  invocations of `tf.function` run eagerly instead of running as a traced graph
  function.

  This can be useful for debugging.

  >>> def my_func(a):
  ...  print("Python side effect")
  ...  return a + a
  >>> a_fn = tf.function(my_func)

  >>> # A side effect the first time the function is traced
  >>> a_fn(tf.constant(1))
  Python side effect
  <tf.Tensor: shape=(), dtype=int32, numpy=2>

  >>> # No further side effect, as the traced function is called
  >>> a_fn(tf.constant(2))
  <tf.Tensor: shape=(), dtype=int32, numpy=4>

  >>> # Now, switch to eager running
  >>> tf.config.run_functions_eagerly(True)
  >>> # Side effect, as the function is called directly
  >>> a_fn(tf.constant(2))
  Python side effect
  <tf.Tensor: shape=(), dtype=int32, numpy=4>

  >>> # Turn this back off
  >>> tf.config.run_functions_eagerly(False)

  Note: This flag has no effect on functions passed into tf.data transformations
  as arguments. tf.data functions are never executed eagerly and are always
  executed as a compiled Tensorflow Graph.

  Args:
    run_eagerly: Boolean. Whether to run functions eagerly.
  """
  global RUN_FUNCTIONS_EAGERLY
  RUN_FUNCTIONS_EAGERLY = bool(run_eagerly)


@deprecation.deprecated(
    None,
    "Use tf.config.functions_run_eagerly instead of the experimental version.")
@tf_export("config.experimental_functions_run_eagerly")
def experimental_functions_run_eagerly():
  """Returns the value of the `experimental_run_functions_eagerly` setting."""
  return functions_run_eagerly()


@tf_export("config.functions_run_eagerly")
def functions_run_eagerly():
  """Returns the value of the `run_functions_eagerly` setting."""
  return RUN_FUNCTIONS_EAGERLY


def _evaluate_var_is_initialized(variables):
  """Compute booleans indicating whether each variable is initialized."""
  with ops.init_scope():
    var_is_initialized = []
    for v in variables:
      var_is_initialized.append(
          resource_variable_ops.var_is_initialized_op(v.handle))
    try:
      return array_ops.stack(var_is_initialized).numpy()
    except errors.UnimplementedError:
      for index, v in enumerate(variables):
        try:
          numpy_value = var_is_initialized[index].numpy()
        except errors.UnimplementedError:
          components = parallel_device.unpack(var_is_initialized[index])
          with ops.device(None):
            components = array_ops.stack(components)
            all_initialized = math_ops.reduce_all(components).numpy()
            any_initialized = math_ops.reduce_any(components).numpy()
          if all_initialized != any_initialized:
            raise NotImplementedError(
                f"Some but not all components of a parallel variable {v!r} "
                "were initialized between their creation in a tf.function and "
                "the function's trace having completed. This is not "
                "supported; consider initializing either all or none of the "
                "components, or moving initialization out of the function.")
          numpy_value = all_initialized
        var_is_initialized[index] = numpy_value
  return var_is_initialized


class FunctionDeleter(object):

  __slots__ = ["func_graph"]

  def __init__(self, func_graph):
    self.func_graph = func_graph

  def __del__(self):
    try:
      func_graph_module.dismantle_func_graph(self.func_graph)
    except:
      pass


class OptionalXlaContext(object):
  """Wrapper for XLA context optionally applied under a context manager."""

  def __init__(self, is_compiled):
    wrap = is_compiled and not control_flow_util.GraphOrParentsInXlaContext( \
              ops.get_default_graph())
    self.xla_context = control_flow_ops.XLAControlFlowContext() \
        if wrap else None

  def __enter__(self):
    if self.xla_context:
      self.xla_context.Enter()

  def __exit__(self, t, value, traceback):
    if self.xla_context:
      self.xla_context.Exit()


@tf_export("__internal__.function.Function", v1=[])
class Function(core.GenericFunction):
  """A `tf.types.experimental.GenericFunction` created by `tf.function`.

  Currently, individual methods/attributes under this class are not guaranteed
  by the TF API contract, and are subject to future changes.
  """

  def __init__(self,
               python_function,
               name,
               input_signature=None,
               autograph=True,
               jit_compile=None,
               experimental_implements=None,
               experimental_autograph_options=None,
               experimental_relax_shapes=False,
               experimental_follow_type_hints=None):
    """Initializes a `Function`.

    Args:
      python_function: the function to be wrapped.
      name: the name given to it.
      input_signature: See the documentation for `tf.function`.
      autograph: See the documentation for `tf.function`.
      jit_compile: See the documentation for `tf.function`.
      experimental_implements: See the documentation for `tf.function`.
      experimental_autograph_options: See the documentation for `tf.function`.
      experimental_relax_shapes: See the documentation for `tf.function`.
      experimental_follow_type_hints: See the documentation for `tf.function`.

    Raises:
      ValueError: if `input_signature` is not None and the `python_function`'s
        argspec has keyword arguments.
    """
    self._lock = threading.Lock()
    self._python_function = python_function
    self._function_spec = function_lib.FunctionSpec.from_function_and_signature(
        python_function,
        input_signature,
        jit_compile=jit_compile,
        experimental_follow_type_hints=experimental_follow_type_hints,
    )
    self._implements = experimental_implements
    self._shared_rendezvous = None
    self._autograph = autograph
    self._experimental_autograph_options = experimental_autograph_options
    self._experimental_relax_shapes = experimental_relax_shapes
    self._jit_compile = jit_compile
    if experimental_follow_type_hints is None:
      experimental_follow_type_hints = False
    self._experimental_follow_type_hints = experimental_follow_type_hints
    self._created_variables = None
    self._stateful_fn = None
    self._stateless_fn = None
    self._descriptor_cache = weakref.WeakKeyDictionary()
    self._name = name
    self._input_signature = input_signature
    self._key_for_call_stats = self._get_key_for_call_stats()
    self._omit_frequent_tracing_warning = False
    ops._tf_function_api_guage.get_cell().set(True)

  def __getstate__(self):
    """Custom pickling, to omit unpickleable objects."""
    result = self.__dict__.copy()
    del result["_lock"]
    del result["_descriptor_cache"]
    del result["_key_for_call_stats"]
    return result

  def __setstate__(self, state):
    """Restore from pickled state."""
    self.__dict__ = state
    self._lock = threading.Lock()
    self._descriptor_cache = weakref.WeakKeyDictionary()
    self._key_for_call_stats = self._get_key_for_call_stats()

  def _get_key_for_call_stats(self):
    """Returns key instance to track call stats and retracings.

    The key instance a best-effort to preserve global consistency.
    """
    target_function = self._python_function
    while hasattr(target_function, "__wrapped__"):
      target_function = target_function.__wrapped__

    if hasattr(target_function, "__func__"):
      target_function = target_function.__func__

    if hasattr(target_function, "__code__"):
      return target_function.__code__

    return self._python_function

  def _defun_with_scope(self, scope):
    """Creates a defun wrapped inside a variable creator scope."""

    weak_wrapped_fn = None
    compile_with_xla = self._jit_compile

    def wrapped_fn(*args, **kwds):
      """Wraps `self._python_function` in a variable creator scope."""
      default_graph = ops.get_default_graph()
      with default_graph._variable_creator_scope(scope, priority=50):
        with OptionalXlaContext(compile_with_xla):
          out = weak_wrapped_fn().__wrapped__(*args, **kwds)
        return out

    weak_wrapped_fn = weakref.ref(wrapped_fn)

    return self._defun(tf_decorator.make_decorator(
        self._python_function,
        wrapped_fn))

  def _create_implements_attribute(self):
    """Creates the attribute value corresponding to IMPLEMENTS_ATTRIBUTE_NAME."""
    attributes = {}
    if isinstance(self._implements, str):
      try:
        implements_attr = six.ensure_text(self._implements, "utf-8")
        attr_value = attr_value_pb2.AttrValue()
        nameattrlist = attr_value_pb2.NameAttrList()
        _text_format.Merge(implements_attr, nameattrlist)
        attr_value.func.CopyFrom(nameattrlist)
        attributes[function_lib.IMPLEMENTS_ATTRIBUTE_NAME] = attr_value
      except (_text_format.ParseError, DecodeError):
        attributes[function_lib.IMPLEMENTS_ATTRIBUTE_NAME] = self._implements
    return attributes

  def _defun(self, fn):
    """Returns a defun generated from the input function."""
    attributes = {}

    if self._implements is not None:
      attributes = self._create_implements_attribute()

    share = self._shared_rendezvous
    if share is not None:
      attributes[function_lib.SHARED_RENDEZVOUS_ATTRIBUTE_NAME] = share

    if self._jit_compile is not None:
      attributes.update(_XlaMustCompile=bool(self._jit_compile))
      if self._jit_compile:
        attributes.update(_noinline=True)
    if not attributes:
      attributes = None
    return function_lib.defun_with_attributes(
        fn,
        input_signature=self.input_signature,
        attributes=attributes,
        autograph=self._autograph,
        jit_compile=self._jit_compile,
        experimental_autograph_options=self._experimental_autograph_options,
        experimental_follow_type_hints=self._experimental_follow_type_hints,
        experimental_relax_shapes=self._experimental_relax_shapes)

  def _initialize(self, args, kwds, add_initializers_to=None):
    """Initializes, on the first call.

    Creates two `Function`s, one that will allow creation of variables
    and one that won't.

    Additionally runs a trace for the `Function` that allows creation
    of variables.

    Args:
      args: Arguments to the underlying python callable.
      kwds: Keyword arguments to the python callable.
      add_initializers_to: Where to collect variable initializers, if not None.
    """

    if self._input_signature is not None:
      arglen = len(self._input_signature)
      arg_names_len = len(self.function_spec.arg_names)
      default_arg_len = len(self.function_spec.fullargspec.defaults or ())
      required_arg_len = arg_names_len - default_arg_len
      if arglen < required_arg_len:
        missing_tensor_specs = self.function_spec.arg_names[
            arglen:required_arg_len]
        raise TypeError(
            f"The decorated function {self._name} has {required_arg_len} "
            f"required argument(s), but tf.function was only passed an "
            f"input_signature of length {arglen}. This covers {arglen} "
            f"required argument(s): {self.function_spec.arg_names[:arglen]}, "
            f"but TensorSpecs are still required for the remaining "
            f"{len(missing_tensor_specs)} argument(s): {missing_tensor_specs}.")

    created_variables = []
    lifted_initializer_graph = func_graph_module.FuncGraph("initializer")

    def variable_capturing_scope(unused_next_creator, **kwds):
      """Creates UnliftedInitializerVariables and saves references to them."""
      v = UnliftedInitializerVariable(
          add_initializers_to=add_initializers_to,
          lifted_initializer_graph=lifted_initializer_graph, **kwds)
      created_variables.append(weakref.ref(v))
      return v

    self._created_variables = created_variables
    self._stateful_fn = self._defun_with_scope(variable_capturing_scope)
    self._stateful_fn._name = self._name
    self._lifted_initializer_graph = lifted_initializer_graph
    self._graph_deleter = FunctionDeleter(self._lifted_initializer_graph)
    self._concrete_stateful_fn = (
        self._stateful_fn._get_concrete_function_internal_garbage_collected(
            *args, **kwds))

    def invalid_creator_scope(*unused_args, **unused_kwds):
      """Disables variable creation."""
      raise ValueError(
          "tf.function only supports singleton tf.Variables created on the "
          "first call. Make sure the tf.Variable is only created once or "
          "created outside tf.function. See "
          "https://www.tensorflow.org/guide/function#creating_tfvariables "
          "for more information.")

    self._stateless_fn = self._defun_with_scope(invalid_creator_scope)
    self._stateless_fn._name = self._name

  def _clone(self, python_function):
    """Clone the function with different python function."""
    f = Function(
        python_function=(self._python_function
                         if python_function is None else python_function),
        name=self._name,
        input_signature=self._input_signature,
        autograph=self._autograph,
        jit_compile=self._jit_compile,
        experimental_implements=self._implements,
        experimental_autograph_options=self._experimental_autograph_options,
        experimental_relax_shapes=self._experimental_relax_shapes,
        experimental_follow_type_hints=self._experimental_follow_type_hints)

    if self._shared_rendezvous:
      f._shared_rendezvous = self._shared_rendezvous

    return f

  def _decorate(self, decorator):
    """Allows the captured Python function to be decorated in place.

    This method is only safe to call when the Function has not been called by a
    user. It makes sense to use this method to push a decorator into the
    function rather than wrapping the function in the decorator.

    We use this in tf.Module to allow user annotated `tf.functions` to remain as
    `Function` objects but still automatically enter the Module name_scope
    when they are evaluated like all other methods.

    Args:
      decorator: A callable accepting a single argument which is the function
        to decorate and returning a callable result.

    Raises:
      ValueError: If the function has been called a ValueError is raised.
    """
    if self._stateful_fn is not None or self._stateless_fn is not None:
      raise ValueError(
          "Functions cannot be decorated after they have been traced.")

    self._python_function = decorator(self._python_function)
    self._function_spec = function_lib.FunctionSpec.from_function_and_signature(
        self._python_function, self.input_signature)

  def _get_tracing_count(self):
    return self.experimental_get_tracing_count()

  def experimental_get_tracing_count(self):
    """Returns the number of times the function has been traced.

    For more information on when a function is traced and when it is
    traced multiple times see https://www.tensorflow.org/guide/function.
    Example:

    >>> @tf.function
    ... def double(a):
    ...   return a + a
    >>> double(tf.constant(1))
    >>> double(tf.constant(2))
    >>> double.experimental_get_tracing_count()
    1
    >>> double(tf.constant("a"))
    >>> double.experimental_get_tracing_count()
    2


    The first time experimental_get_tracing_count is called
    it returns 1, as the function is traced the first
    time it is called, and the second time the same graph is used
    since we're calling it with a parameter of the same type.

    The second time experimental_get_tracing_count is called
    it returns 2, as we called double with a
    different argument type, and so it was traced again.

    """
    result = self._stateless_fn.tracing_count if self._stateless_fn else 0
    result += self._stateful_fn.tracing_count if self._stateful_fn else 0
    return result

  @property
  def _run_functions_eagerly(self):
    return RUN_FUNCTIONS_EAGERLY

  @traceback_utils.filter_traceback
  def __call__(self, *args, **kwds):
    if self._run_functions_eagerly:
      with trace.Trace(self._name, tf_function_call="eager"):
        return self._python_function(*args, **kwds)

    if self._created_variables is None:
      compiled = bool(self._jit_compile and
                      not control_flow_util.GraphOrParentsInXlaContext(
                          ops.get_default_graph()))
      if ops.executing_eagerly_outside_functions() and (
          context.executing_eagerly() or compiled):
        _tf_function_counter.get_cell(str(int(compiled))).increase_by(1)

    tracing_count = self.experimental_get_tracing_count()
    with trace.Trace(self._name) as tm:
      compiler = "xla" if self._jit_compile else "nonXla"

      with OptionalXlaContext(self._jit_compile):
        result = self._call(*args, **kwds)

      new_tracing_count = self.experimental_get_tracing_count()
      without_tracing = (tracing_count == new_tracing_count)
      execution_mode = "notTraced" if without_tracing else "traced"
      tm.set_metadata(tf_function_call=execution_mode + "-" + compiler,
                      tracing_count=new_tracing_count)

    if context.executing_eagerly():
      if without_tracing:
        _frequent_tracing_detector_manager.called_without_tracing(
            self._key_for_call_stats)
      else:
        _frequent_tracing_detector_manager.called_with_tracing(
            self._key_for_call_stats, self._python_function,
            self._omit_frequent_tracing_warning)

    return result

  def _call(self, *args, **kwds):
    """Calls the graph function."""
    self._lock.acquire()
    if ALLOW_DYNAMIC_VARIABLE_CREATION:
      condition = self._created_variables and self._stateful_fn is None
    else:
      condition = self._created_variables
    if condition:
      self._lock.release()
      return self._stateless_fn(*args, **kwds)
    elif self._stateful_fn is not None:
      self._lock.release()
      results = self._stateful_fn(*args, **kwds)
      if self._created_variables and not ALLOW_DYNAMIC_VARIABLE_CREATION:
        raise ValueError("Creating variables on a non-first call to a function"
                         " decorated with tf.function.")
      return results

    try:
      initializers = []
      self._initialize(args, kwds, add_initializers_to=initializers)
    finally:
      self._lock.release()

    if self._created_variables:
      try:
        self._initialize_uninitialized_variables(initializers)
      except lift_to_graph.UnliftableError:
        pass
      else:
        return self._stateless_fn(*args, **kwds)
    else:
      _, _, _, filtered_flat_args = \
          self._stateful_fn._function_spec.canonicalize_function_inputs(
              *args, **kwds)
      return self._concrete_stateful_fn._call_flat(
          filtered_flat_args, self._concrete_stateful_fn.captured_inputs)

    def fn_with_cond(inner_args, inner_kwds, inner_filtered_flat_args):
      """Conditionally runs initialization if it's needed."""
      condition = True
      for wr in self._created_variables:
        variable = wr()
        if variable is None:
          raise ValueError(
              "A tf.Variable created inside your tf.function has been"
              " garbage-collected. Your code needs to keep Python references"
              " to variables created inside `tf.function`s.\n"
              "\n"
              "A common way to raise this error is to create and return a"
              " variable only referenced inside your function:\n"
              "\n"
              "@tf.function\n"
              "def f():\n"
              "  v = tf.Variable(1.0)\n"
              "  return v\n"
              "\n"
              "v = f()  # Crashes with this error message!\n"
              "\n"
              "The reason this crashes is that @tf.function annotated"
              " function returns a **`tf.Tensor`** with the **value** of the"
              " variable when the function is called rather than the"
              " variable instance itself. As such there is no code holding a"
              " reference to the `v` created inside the function and Python"
              " garbage collects it.\n"
              "\n"
              "The simplest way to fix this issue is to create variables"
              " outside the function and capture them:\n"
              "\n"
              "v = tf.Variable(1.0)\n"
              "\n"
              "@tf.function\n"
              "def f():\n"
              "  return v\n"
              "\n"
              "f()  # <tf.Tensor: numpy=1.>\n"
              "v.assign_add(1.)\n"
              "f()  # <tf.Tensor: numpy=2.>")
        condition = math_ops.logical_and(
            condition, resource_variable_ops.var_is_initialized_op(
                variable.handle))
      return control_flow_ops.cond(
          condition,
          lambda: self._stateless_fn(*inner_args, **inner_kwds),
          functools.partial(
              self._concrete_stateful_fn._call_flat,
              inner_filtered_flat_args,
              captured_inputs=self._concrete_stateful_fn.captured_inputs))

    canon_args, canon_kwds, _, filtered_flat_args = \
        self._stateful_fn._function_spec.canonicalize_function_inputs(
            *args, **kwds)
    return function_lib.defun(fn_with_cond)(canon_args, canon_kwds,
                                            filtered_flat_args)

  def experimental_get_compiler_ir(self, *args, **kwargs):
    context.ensure_initialized()
    if not self._jit_compile:
      raise ValueError("Compiler IR can only be returned for functions marked "
                       "with 'jit_compile=True'")

    concrete_fn = self.get_concrete_function(*args, **kwargs)
    fn_name = concrete_fn.name

    _, _, _, filtered_flat_args = \
        concrete_fn._function_spec.canonicalize_function_inputs(
            *args, **kwargs)

    def compiler_ir_generator(stage="hlo", device_name=None):
      if device_name is None:
        device_name = random_ops.random_normal([]).device
      res_bytes = context.context().get_compiler_ir(
          device_name=device_name,
          stage=stage,
          function_name=fn_name,
          args=list(filtered_flat_args) + concrete_fn.captured_inputs)
      if stage in ("hlo_serialized", "optimized_hlo_serialized",
                   "optimized_hlo_proto_serialized"):
        return res_bytes
      else:
        return res_bytes.decode("utf-8")

    return compiler_ir_generator

  @property
  def python_function(self):
    """The python function wrapped in this tf.function."""
    return self._python_function

  @property
  def input_signature(self):
    return self._function_spec.input_signature

  @property
  def function_spec(self):
    return self._function_spec

  def pretty_printed_concrete_signatures(self, verbose=True):
    joiner = "\n\n" if verbose else "\n"
    return joiner.join([
        c.pretty_printed_signature(verbose=verbose)
        for c in self._list_all_concrete_functions()
    ])

  def _initialize_uninitialized_variables(self, initializers):
    """Make and call a `ConcreteFunction` which initializes variables."""

    if not initializers:
      return

    var_is_initialized = _evaluate_var_is_initialized(
        [v for v, _ in initializers])

    @function_lib.defun(autograph=False)
    def initialize_variables():
      op_map = object_identity.ObjectIdentityDictionary()

      inits = []
      for (v, init), is_initialized in zip(initializers, var_is_initialized):
        with ops.init_scope():
          if is_initialized:
            continue
        inits.append(init)

      if inits:
        op_map = lift_to_graph.lift_to_graph(
            inits, ops.get_default_graph(), op_map=op_map)
      for (v, init), is_initialized in zip(initializers, var_is_initialized):
        with ops.init_scope():
          if is_initialized:
            continue
        v.assign(op_map[init], read_value=False)

    with ops.init_scope():
      return initialize_variables.get_concrete_function()()

  def get_initialization_function(self, *args, **kwargs):
    """Returns a `ConcreteFunction` which initializes this function's variables.

    Requires that this function hasn't been accessed yet through either calling
    it or calling get_concrete_function. Fails if we cannot build an initializer
    function which does not depend on the concrete values of the inputs to this
    function.

    Note that running this function will overwrite any values currently assigned
    to variables, for example restores from a checkpoint.

    Args:
      *args: arguments to the underlying python callable.
      **kwargs: keyword arguments to the python callable.

    Returns:
      A `ConcreteFunction` object which initializes the variables of this
      function.

    Raises:
      RuntimeError: if called after the variables have been initialized.
    """
    with self._lock:
      if self._stateful_fn is not None:
        raise RuntimeError(
            "get_initialization_function cannot be called after the function "
            "has been used")
      initializers = []
      self._initialize(args, kwargs, add_initializers_to=initializers)

    @function_lib.defun
    def initialize_variables():
      for v, init in initializers:
        v.assign(
            lift_to_graph.lift_to_graph([init], ops.get_default_graph())[init],
            read_value=False)

    return initialize_variables.get_concrete_function()

  def _list_all_concrete_functions(self):
    """Returns all concrete functions."""
    if self.input_signature is not None:
      self.get_concrete_function()
    concrete_functions = []
    if self._stateful_fn:
      concrete_functions.extend(
          self._stateful_fn._function_cache.all_values())
    if self._stateless_fn:
      concrete_functions.extend(
          self._stateless_fn._function_cache.all_values())
    return concrete_functions

  def _list_all_concrete_functions_for_serialization(self):
    """Returns all concrete functions for serialization.

    Returns:
      A list of instances of `ConcreteFunction`.
    """
    concrete_functions = self._list_all_concrete_functions()
    seen_signatures = []
    for concrete_function in concrete_functions:
      signature = concrete_function.structured_input_signature
      flattened = nest.flatten(signature)
      if any(
          isinstance(arg, func_graph_module.UnknownArgument)
          for arg in flattened):
        logging.info("Unsupported signature for serialization: %s.", signature)
        continue
      equal_to_signature = functools.partial(
          function_lib.is_same_structure, signature, check_values=True)
      if not any(equal_to_signature(s) for s in seen_signatures):
        seen_signatures.append(signature)

    concrete_functions = []
    for args, kwargs in seen_signatures:
      concrete_functions.append(self.get_concrete_function(*args, **kwargs))
    return concrete_functions

  def _get_concrete_function_garbage_collected(self, *args, **kwargs):
    """Returns a `ConcreteFunction` specialized to inputs and execution context.

    Unlike `get_concrete_function(...)`, the graph will be deleted when the
    returned function is deleted.  It's useful to avoid creating a reference
    cycle when you know for sure that the graph will be no longer used without
    the returned function.

    Args:
      *args: inputs to specialize on.
      **kwargs: inputs to specialize on.

    Returns:
      A TensorFlow function which takes exactly one `tf.Tensor` per argument.

    Raises:
      ValueError: if this object has not yet been called on concrete values.
    """
    with self._lock:
      if self._stateful_fn is None:
        initializers = []
        self._initialize(args, kwargs, add_initializers_to=initializers)
        self._initialize_uninitialized_variables(initializers)

    if self._created_variables:
      return self._stateless_fn._get_concrete_function_garbage_collected(
          *args, **kwargs)
    elif self._stateful_fn is not None:
      concrete = self._stateful_fn._get_concrete_function_garbage_collected(
          *args, **kwargs)
      if self._created_variables:
        raise ValueError("Creating variables on a non-first call to a function"
                         " decorated with tf.function.")
      return concrete

  def get_concrete_function(self, *args, **kwargs):
    concrete = self._get_concrete_function_garbage_collected(*args, **kwargs)
    concrete._garbage_collector.release()
    return concrete

  def __get__(self, instance, owner):
    """Makes it possible to defun instance methods."""
    del owner
    if (isinstance(instance, composite_tensor.CompositeTensor) and
        instance._type_spec is not None):
      return types_lib.MethodType(self, instance)
    if instance not in self._descriptor_cache:
      if instance is None:
        return self
      self._descriptor_cache[instance] = (
          function_lib.class_method_to_instance_method(self, instance))
    return self._descriptor_cache[instance]


@tf_export("function")
@deprecation.deprecated_args(None,
                             "experimental_compile is deprecated, use "
                             "jit_compile instead", "experimental_compile")
def function(func=None,
             input_signature=None,
             autograph=True,
             jit_compile=None,
             experimental_implements=None,
             experimental_autograph_options=None,
             experimental_relax_shapes=False,
             experimental_compile=None,
             experimental_follow_type_hints=None) -> core.GenericFunction:
  """Compiles a function into a callable TensorFlow graph.

  `tf.function` constructs a `tf.types.experimental.GenericFunction` that
  executes a TensorFlow graph (`tf.Graph`) created by trace-compiling the
  TensorFlow operations in `func`. More information on the topic can be found
  in [Introduction to Graphs and tf.function]
  (https://www.tensorflow.org/guide/intro_to_graphs).

  See [Better Performance with tf.function]
  (https://www.tensorflow.org/guide/function) for tips on performance and
  known limitations.

  Example usage:

  >>> @tf.function
  ... def f(x, y):
  ...   return x ** 2 + y
  >>> x = tf.constant([2, 3])
  >>> y = tf.constant([3, -2])
  >>> f(x, y)
  <tf.Tensor: ... numpy=array([7, 7], ...)>

  The trace-compilation allows non-TensorFlow operations to execute, but under
  special conditions. In general, only TensorFlow operations are guaranteed to
  run and create fresh results whenever the `GenericFunction` is called.

  ## Features

  `func` may use data-dependent control flow, including `if`, `for`, `while`
  `break`, `continue` and `return` statements:

  >>> @tf.function
  ... def f(x):
  ...   if tf.reduce_sum(x) > 0:
  ...     return x * x
  ...   else:
  ...     return -x // 2
  >>> f(tf.constant(-2))
  <tf.Tensor: ... numpy=1>

  `func`'s closure may include `tf.Tensor` and `tf.Variable` objects:

  >>> @tf.function
  ... def f():
  ...   return x ** 2 + y
  >>> x = tf.constant([-2, -3])
  >>> y = tf.Variable([3, -2])
  >>> f()
  <tf.Tensor: ... numpy=array([7, 7], ...)>

  `func` may also use ops with side effects, such as `tf.print`, `tf.Variable`
  and others:

  >>> v = tf.Variable(1)
  >>> @tf.function
  ... def f(x):
  ...   for i in tf.range(x):
  ...     v.assign_add(i)
  >>> f(3)
  >>> v
  <tf.Variable ... numpy=4>

  Important: Any Python side-effects (appending to a list, printing with
  `print`, etc) will only happen once, when `func` is traced. To have
  side-effects executed into your `tf.function` they need to be written
  as TF ops:

  >>> l = []
  >>> @tf.function
  ... def f(x):
  ...   for i in x:
  ...     l.append(i + 1)    # Caution! Will only happen once when tracing
  >>> f(tf.constant([1, 2, 3]))
  >>> l
  [<tf.Tensor ...>]

  Instead, use TensorFlow collections like `tf.TensorArray`:

  >>> @tf.function
  ... def f(x):
  ...   ta = tf.TensorArray(dtype=tf.int32, size=0, dynamic_size=True)
  ...   for i in range(len(x)):
  ...     ta = ta.write(i, x[i] + 1)
  ...   return ta.stack()
  >>> f(tf.constant([1, 2, 3]))
  <tf.Tensor: ..., numpy=array([2, 3, 4], ...)>

  ## `tf.function` creates polymorphic callables

  Internally, `tf.types.experimental.GenericFunction` may contain multiple
  `tf.types.experimental.ConcreteFunction`s, each specialized to arguments with
  different data types or shapes, since TensorFlow can perform more
  optimizations on graphs of specific shapes, dtypes and values of constant
  arguments. `tf.function` treats any pure Python values as opaque objects (best
  thought of as compile-time constants), and builds a separate `tf.Graph` for
  each set of Python arguments that it encounters.
  For more information, see the
  [tf.function guide](https://www.tensorflow.org/guide/function#rules_of_tracing)

  Executing a `GenericFunction` will select and execute the appropriate
  `ConcreteFunction` based on the argument types and values.

  To obtain an individual `ConcreteFunction`, use the
  `GenericFunction.get_concrete_function` method. It can be called with the
  same arguments as `func` and returns a
  `tf.types.experimental.ConcreteFunction`. `ConcreteFunction`s are backed by a
  single `tf.Graph`:

  >>> @tf.function
  ... def f(x):
  ...   return x + 1
  >>> isinstance(f.get_concrete_function(1).graph, tf.Graph)
  True

  `ConcreteFunction`s can be executed just like `GenericFunction`s, but their
  input is resticted to the types to which they're specialized.

  ## Retracing

  `ConcreteFunctions` are built (traced) on the fly, as the `GenericFunction` is
  called with new TensorFlow types or shapes, or with new Python values as
  arguments. When `GenericFunction` builds a new trace, it is said that `func`
  is retraced. Retracing is a frequent performance concern for `tf.function` as
  it can be considerably slower than executing a graph that's already been
  traced. It is ideal to minimize the amount of retracing in your code.

  Caution: Passing python scalars or lists as arguments to `tf.function` will
  usually retrace. To avoid this, pass numeric arguments as Tensors whenever
  possible:

  >>> @tf.function
  ... def f(x):
  ...   return tf.abs(x)
  >>> f1 = f.get_concrete_function(1)
  >>> f2 = f.get_concrete_function(2)  # Slow - compiles new graph
  >>> f1 is f2
  False
  >>> f1 = f.get_concrete_function(tf.constant(1))
  >>> f2 = f.get_concrete_function(tf.constant(2))  # Fast - reuses f1
  >>> f1 is f2
  True

  Python numerical arguments should only be used when they take few distinct
  values, such as hyperparameters like the number of layers in a neural network.

  ## Input signatures

  For Tensor arguments, `GenericFunction`creates a new `ConcreteFunction` for
  every unique set of input shapes and datatypes. The example below creates two
  separate `ConcreteFunction`s, each specialized to a different shape:

  >>> @tf.function
  ... def f(x):
  ...   return x + 1
  >>> vector = tf.constant([1.0, 1.0])
  >>> matrix = tf.constant([[3.0]])
  >>> f.get_concrete_function(vector) is f.get_concrete_function(matrix)
  False

  An "input signature" can be optionally provided to `tf.function` to control
  this process. The input signature specifies the shape and type of each
  Tensor argument to the function using a `tf.TensorSpec` object. More general
  shapes can be used. This ensures only one `ConcreteFunction` is created, and
  restricts the `GenericFunction` to the specified shapes and types. It is
  an effective way to limit retracing when Tensors have dynamic shapes.

  >>> @tf.function(
  ...     input_signature=[tf.TensorSpec(shape=None, dtype=tf.float32)])
  ... def f(x):
  ...   return x + 1
  >>> vector = tf.constant([1.0, 1.0])
  >>> matrix = tf.constant([[3.0]])
  >>> f.get_concrete_function(vector) is f.get_concrete_function(matrix)
  True

  ## Variables may only be created once

  `tf.function` only allows creating new `tf.Variable` objects when it is called
  for the first time:

  >>> class MyModule(tf.Module):
  ...   def __init__(self):
  ...     self.v = None
  ...
  ...   @tf.function
  ...   def __call__(self, x):
  ...     if self.v is None:
  ...       self.v = tf.Variable(tf.ones_like(x))
  ...     return self.v * x

  In general, it is recommended to create `tf.Variable`s outside of
  `tf.function`.
  In simple cases, persisting state across `tf.function` boundaries may be
  implemented using a pure functional style in which state is represented by
  `tf.Tensor`s passed as arguments and returned as return values.

  Contrast the two styles below:

  >>> state = tf.Variable(1)
  >>> @tf.function
  ... def f(x):
  ...   state.assign_add(x)
  >>> f(tf.constant(2))  # Non-pure functional style
  >>> state
  <tf.Variable ... numpy=3>

  >>> state = tf.constant(1)
  >>> @tf.function
  ... def f(state, x):
  ...   state += x
  ...   return state
  >>> state = f(state, tf.constant(2))  # Pure functional style
  >>> state
  <tf.Tensor: ... numpy=3>

  ## Python operations execute only once per trace

  `func` may contain TensorFlow operations mixed with pure Python operations.
  However, when the function is executed, only the TensorFlow operations will
  run. The Python operations run only once, at trace time. If TensorFlow
  operations depend on results from Pyhton operations, those results will be
  frozen into the graph.

  >>> @tf.function
  ... def f(a, b):
  ...   print('this runs at trace time; a is', a, 'and b is', b)
  ...   return b
  >>> f(1, tf.constant(1))
  this runs at trace time; a is 1 and b is Tensor("...", shape=(), dtype=int32)
  <tf.Tensor: shape=(), dtype=int32, numpy=1>

  >>> f(1, tf.constant(2))
  <tf.Tensor: shape=(), dtype=int32, numpy=2>

  >>> f(2, tf.constant(1))
  this runs at trace time; a is 2 and b is Tensor("...", shape=(), dtype=int32)
  <tf.Tensor: shape=(), dtype=int32, numpy=1>

  >>> f(2, tf.constant(2))
  <tf.Tensor: shape=(), dtype=int32, numpy=2>

  ## Using type annotations to improve performance

  'experimental_follow_type_hints` can be used along with type annotations to
  reduce retracing by automatically casting any Python values to `tf.Tensor`
  (something that is not done by default, unless you use input signatures).

  >>> @tf.function(experimental_follow_type_hints=True)
  ... def f_with_hints(x: tf.Tensor):
  ...   print('Tracing')
  ...   return x
  >>> @tf.function(experimental_follow_type_hints=False)
  ... def f_no_hints(x: tf.Tensor):
  ...   print('Tracing')
  ...   return x
  >>> f_no_hints(1)
  Tracing
  <tf.Tensor: shape=(), dtype=int32, numpy=1>
  >>> f_no_hints(2)
  Tracing
  <tf.Tensor: shape=(), dtype=int32, numpy=2>
  >>> f_with_hints(1)
  Tracing
  <tf.Tensor: shape=(), dtype=int32, numpy=1>
  >>> f_with_hints(2)
  <tf.Tensor: shape=(), dtype=int32, numpy=2>

  Args:
    func: the function to be compiled. If `func` is None, `tf.function` returns
      a decorator that can be invoked with a single argument - `func`. In other
      words, `tf.function(input_signature=...)(func)` is equivalent to
      `tf.function(func, input_signature=...)`. The former can be used as
      decorator.
    input_signature: A possibly nested sequence of `tf.TensorSpec` objects
      specifying the shapes and dtypes of the Tensors that will be supplied to
      this function. If `None`, a separate function is instantiated for each
      inferred input signature.  If input_signature is specified, every input to
      `func` must be a `Tensor`, and `func` cannot accept `**kwargs`.
    autograph: Whether autograph should be applied on `func` before tracing a
      graph. Data-dependent control flow requires `autograph=True`. For more
      information, see the [tf.function and AutoGraph guide](
      https://www.tensorflow.org/guide/function#autograph_transformations).
    jit_compile: If `True`, compiles the function using
      [XLA](https://tensorflow.org/xla). XLA performs compiler optimizations,
      such as fusion, and attempts to emit more efficient code. This may
      drastically improve the performance. If set to `True`,
      the whole function needs to be compilable by XLA, or an
      `errors.InvalidArgumentError` is thrown.
      If `None` (default), compiles the function with XLA when running on TPU
      and goes through the regular function execution path when running on
      other devices.
      If `False`, executes the function without XLA compilation.  Set this value
      to `False` when directly running a multi-device function on TPUs (e.g. two
      TPU cores, one TPU core and its host CPU).
      Not all functions are compilable, see a list of
      [sharp corners](https://tensorflow.org/xla/known_issues).
    experimental_implements: If provided, contains a name of a "known" function
      this implements. For example "mycompany.my_recurrent_cell".
      This is stored as an attribute in inference function,
      which can then be detected when processing serialized function.
      See [standardizing composite ops](https://github.com/tensorflow/community/blob/master/rfcs/20190610-standardizing-composite_ops.md)  # pylint: disable=line-too-long
      for details.  For an example of utilizing this attribute see this
      [example](https://github.com/tensorflow/tensorflow/blob/master/tensorflow/compiler/mlir/lite/transforms/prepare_composite_functions_tf.cc)
      The code above automatically detects and substitutes function that
      implements "embedded_matmul" and allows TFLite to substitute its own
      implementations. For instance, a tensorflow user can use this
       attribute to mark that their function also implements
      `embedded_matmul` (perhaps more efficiently!)
      by specifying it using this parameter:
      `@tf.function(experimental_implements="embedded_matmul")`
      This can either be specified as just the string name of the function or
      a NameAttrList corresponding to a list of key-value attributes associated
      with the function name. The name of the function will be in the 'name'
      field of the NameAttrList. To define a formal TF op for this function
      implements, try the experimental [composite TF](https://github.com/tensorflow/tensorflow/blob/master/tensorflow/compiler/mlir/tfr)
      project.
    experimental_autograph_options: Optional tuple of
      `tf.autograph.experimental.Feature` values.
    experimental_relax_shapes: When True, `tf.function` may generate fewer,
      graphs that are less specialized on input shapes.
    experimental_compile: Deprecated alias to 'jit_compile'.
    experimental_follow_type_hints: When True, the function may use type
      annotations from `func` to optimize the tracing performance. For example,
      arguments annotated with `tf.Tensor` will automatically be converted
      to a Tensor.

  Returns:
     If `func` is not None, returns a `tf.types.experimental.GenericFunction`.
     If `func` is None, returns a decorator that, when invoked with a single
     `func` argument, returns a `tf.types.experimental.GenericFunction`.

  Raises:
     `ValueError` when attempting to use `jit_compile=True`, but XLA support is
     not available.
  """
  if func is not None:
    function_lib.validate_python_function(func)
  if input_signature is not None:
    function_lib.validate_signature(input_signature)
  if experimental_follow_type_hints is None:
    experimental_follow_type_hints = False

  def decorated(inner_function):
    try:
      name = inner_function.__name__
    except AttributeError:
      name = "function"
    return tf_decorator.make_decorator(
        inner_function,
        decorator_name="tf.function",
        decorator_func=Function(
            inner_function,
            name,
            input_signature=input_signature,
            autograph=autograph,
            experimental_autograph_options=experimental_autograph_options,
            experimental_relax_shapes=experimental_relax_shapes,

            jit_compile=deprecation.deprecated_argument_lookup(
                "jit_compile",
                jit_compile,
                "experimental_compile",
                experimental_compile),
            experimental_implements=experimental_implements,
            experimental_follow_type_hints=experimental_follow_type_hints))

  if func is not None:
    return decorated(func)

  return decorated
