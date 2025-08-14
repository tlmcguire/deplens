from dataclasses import dataclass

import vyper.utils as util
from vyper.address_space import MEMORY
from vyper.codegen.abi_encoder import abi_encode
from vyper.codegen.core import (
    calculate_type_for_external_return,
    check_assign,
    check_external_call,
    dummy_node_for_type,
    make_setter,
    needs_clamp,
    unwrap_location,
    wrap_value_for_external_return,
)
from vyper.codegen.ir_node import Encoding, IRnode
from vyper.codegen.types import InterfaceType, TupleType, get_type_for_exact_size
from vyper.codegen.types.convert import new_type_to_old_type
from vyper.exceptions import TypeCheckFailure
from vyper.semantics.types.function import StateMutability


@dataclass
class _CallKwargs:
    value: IRnode
    gas: IRnode
    skip_contract_check: bool
    default_return_value: IRnode


def _pack_arguments(fn_type, args, context):
    args_tuple_t = TupleType([x.typ for x in args])
    args_as_tuple = IRnode.from_list(["multi"] + [x for x in args], typ=args_tuple_t)
    args_abi_t = args_tuple_t.abi_type

    dst_tuple_t = TupleType(
        [new_type_to_old_type(typ) for typ in fn_type.arguments.values()][: len(args)]
    )
    check_assign(dummy_node_for_type(dst_tuple_t), args_as_tuple)

    if fn_type.return_type is not None:
        return_abi_t = calculate_type_for_external_return(fn_type.return_type).abi_type

        buflen = max(args_abi_t.size_bound(), return_abi_t.size_bound())
    else:
        buflen = args_abi_t.size_bound()

    buflen += 32

    buf_t = get_type_for_exact_size(buflen)
    buf = context.new_internal_variable(buf_t)

    args_ofst = buf + 28
    args_len = args_abi_t.size_bound() + 4

    abi_signature = fn_type.name + dst_tuple_t.abi_type.selector_name()

    pack_args = ["seq"]
    pack_args.append(["mstore", buf, util.abi_method_id(abi_signature)])

    if len(args) != 0:
        pack_args.append(abi_encode(buf + 32, args_as_tuple, context, bufsz=buflen))

    return buf, pack_args, args_ofst, args_len


def _unpack_returndata(buf, fn_type, call_kwargs, contract_address, context, expr):
    ast_return_t = fn_type.return_type

    if ast_return_t is None:
        return ["pass"], 0, 0

    return_t = new_type_to_old_type(ast_return_t)

    wrapped_return_t = calculate_type_for_external_return(return_t)

    abi_return_t = wrapped_return_t.abi_type

    min_return_size = abi_return_t.min_size()
    max_return_size = abi_return_t.size_bound()
    assert 0 < min_return_size <= max_return_size

    ret_ofst = buf
    ret_len = max_return_size

    encoding = Encoding.ABI

    buf = IRnode.from_list(
        buf,
        typ=wrapped_return_t,
        location=MEMORY,
        encoding=encoding,
        annotation=f"{expr.node_source_code} returndata buffer",
    )

    unpacker = ["seq"]

    if not call_kwargs.skip_contract_check:
        unpacker.append(["assert", ["ge", "returndatasize", min_return_size]])

    assert isinstance(wrapped_return_t, TupleType)

    if needs_clamp(wrapped_return_t, encoding):
        return_buf = context.new_internal_variable(wrapped_return_t)
        return_buf = IRnode.from_list(return_buf, typ=wrapped_return_t, location=MEMORY)

        unpacker.append(make_setter(return_buf, buf))
    else:
        return_buf = buf

    if call_kwargs.default_return_value is not None:

        override_value = wrap_value_for_external_return(call_kwargs.default_return_value)
        stomp_return_buffer = ["seq"]
        if not call_kwargs.skip_contract_check:
            stomp_return_buffer.append(_extcodesize_check(contract_address))
        stomp_return_buffer.append(make_setter(return_buf, override_value))
        unpacker = ["if", ["eq", "returndatasize", 0], stomp_return_buffer, unpacker]

    unpacker = ["seq", unpacker, return_buf]

    return unpacker, ret_ofst, ret_len


def _parse_kwargs(call_expr, context):
    from vyper.codegen.expr import Expr

    def _bool(x):
        assert x.value in (0, 1), "type checker missed this"
        return bool(x.value)

    call_kwargs = {kw.arg: Expr(kw.value, context).ir_node for kw in call_expr.keywords}

    ret = _CallKwargs(
        value=unwrap_location(call_kwargs.pop("value", IRnode(0))),
        gas=unwrap_location(call_kwargs.pop("gas", IRnode("gas"))),
        skip_contract_check=_bool(call_kwargs.pop("skip_contract_check", IRnode(0))),
        default_return_value=call_kwargs.pop("default_return_value", None),
    )

    if len(call_kwargs) != 0:
        raise TypeCheckFailure(f"Unexpected keyword arguments: {call_kwargs}")

    return ret


def _extcodesize_check(address):
    return ["assert", ["extcodesize", address]]


def ir_for_external_call(call_expr, context):
    from vyper.codegen.expr import Expr

    contract_address = Expr.parse_value_expr(call_expr.func.value, context)
    call_kwargs = _parse_kwargs(call_expr, context)
    args_ir = [Expr(x, context).ir_node for x in call_expr.args]

    assert isinstance(contract_address.typ, InterfaceType)

    fn_type = call_expr.func._metadata["type"]

    assert fn_type.min_arg_count <= len(args_ir) <= fn_type.max_arg_count

    ret = ["seq"]

    buf, arg_packer, args_ofst, args_len = _pack_arguments(fn_type, args_ir, context)

    ret_unpacker, ret_ofst, ret_len = _unpack_returndata(
        buf, fn_type, call_kwargs, contract_address, context, call_expr
    )

    ret += arg_packer

    if fn_type.return_type is None and not call_kwargs.skip_contract_check:
        ret.append(_extcodesize_check(contract_address))

    gas = call_kwargs.gas
    value = call_kwargs.value

    use_staticcall = fn_type.mutability in (StateMutability.VIEW, StateMutability.PURE)
    if context.is_constant():
        assert use_staticcall, "typechecker missed this"

    if use_staticcall:
        call_op = ["staticcall", gas, contract_address, args_ofst, args_len, buf, ret_len]
    else:
        call_op = ["call", gas, contract_address, value, args_ofst, args_len, buf, ret_len]

    ret.append(check_external_call(call_op))

    return_t = None
    if fn_type.return_type is not None:
        return_t = new_type_to_old_type(fn_type.return_type)
        ret.append(ret_unpacker)

    return IRnode.from_list(ret, typ=return_t, location=MEMORY)
