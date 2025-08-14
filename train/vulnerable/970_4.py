import vyper.utils as util
from vyper.address_space import MEMORY
from vyper.codegen.abi_encoder import abi_encode
from vyper.codegen.core import (
    calculate_type_for_external_return,
    check_assign,
    check_external_call,
    dummy_node_for_type,
    get_element_ptr,
)
from vyper.codegen.ir_node import Encoding, IRnode
from vyper.codegen.types import InterfaceType, TupleType, get_type_for_exact_size
from vyper.exceptions import StateAccessViolation, TypeCheckFailure


def _pack_arguments(contract_sig, args, context):
    args_tuple_t = TupleType([x.typ for x in args])
    args_as_tuple = IRnode.from_list(["multi"] + [x for x in args], typ=args_tuple_t)
    args_abi_t = args_tuple_t.abi_type

    dst_tuple_t = TupleType([arg.typ for arg in contract_sig.args][: len(args)])
    check_assign(dummy_node_for_type(dst_tuple_t), args_as_tuple)

    if contract_sig.return_type is not None:
        return_abi_t = calculate_type_for_external_return(contract_sig.return_type).abi_type

        buflen = max(args_abi_t.size_bound(), return_abi_t.size_bound())
    else:
        buflen = args_abi_t.size_bound()

    buflen += 32

    buf_t = get_type_for_exact_size(buflen)
    buf = context.new_internal_variable(buf_t)

    args_ofst = buf + 28
    args_len = args_abi_t.size_bound() + 4

    abi_signature = contract_sig.name + dst_tuple_t.abi_type.selector_name()

    mstore_method_id = [["mstore", buf, util.abi_method_id(abi_signature)]]

    if len(args) == 0:
        encode_args = ["pass"]
    else:
        encode_args = abi_encode(buf + 32, args_as_tuple, context, bufsz=buflen)

    return buf, mstore_method_id + [encode_args], args_ofst, args_len


def _returndata_encoding(contract_sig):
    if contract_sig.is_from_json:
        return Encoding.JSON_ABI
    return Encoding.ABI


def _unpack_returndata(buf, contract_sig, skip_contract_check, context):
    return_t = contract_sig.return_type
    if return_t is None:
        return ["pass"], 0, 0

    return_t = calculate_type_for_external_return(return_t)
    should_unwrap_abi_tuple = return_t != contract_sig.return_type

    abi_return_t = return_t.abi_type

    min_return_size = abi_return_t.min_size()
    max_return_size = abi_return_t.size_bound()
    assert 0 < min_return_size <= max_return_size

    ret_ofst = buf
    ret_len = max_return_size

    ret = []
    if not skip_contract_check:
        ret += [["assert", ["gt", "returndatasize", min_return_size - 1]]]


    buf = IRnode(buf, typ=return_t, encoding=_returndata_encoding(contract_sig), location=MEMORY)

    if should_unwrap_abi_tuple:
        buf = get_element_ptr(buf, 0, array_bounds_check=False)

    ret += [buf]

    return ret, ret_ofst, ret_len


def _external_call_helper(
    contract_address,
    contract_sig,
    args_ir,
    context,
    value=None,
    gas=None,
    skip_contract_check=None,
    expr=None,
):

    if value is None:
        value = 0
    if gas is None:
        gas = "gas"
    if skip_contract_check is None:
        skip_contract_check = False

    assert len(contract_sig.base_args) <= len(args_ir) <= len(contract_sig.args)

    if context.is_constant() and contract_sig.mutability not in ("view", "pure"):
        raise StateAccessViolation(
            f"May not call state modifying function '{contract_sig.name}' "
            f"within {context.pp_constancy()}.",
            expr,
        )

    sub = ["seq"]

    buf, arg_packer, args_ofst, args_len = _pack_arguments(contract_sig, args_ir, context)

    ret_unpacker, ret_ofst, ret_len = _unpack_returndata(
        buf, contract_sig, skip_contract_check, context
    )

    sub += arg_packer

    if contract_sig.return_type is None and not skip_contract_check:
        sub.append(["assert", ["extcodesize", contract_address]])

    if context.is_constant() or contract_sig.mutability in ("view", "pure"):
        call_op = ["staticcall", gas, contract_address, args_ofst, args_len, ret_ofst, ret_len]
    else:
        call_op = ["call", gas, contract_address, value, args_ofst, args_len, ret_ofst, ret_len]

    sub.append(check_external_call(call_op))

    if contract_sig.return_type is not None:
        sub += ret_unpacker

    ret = IRnode.from_list(
        sub,
        typ=contract_sig.return_type,
        location=MEMORY,
        encoding=_returndata_encoding(contract_sig),
    )

    return ret


def _get_special_kwargs(stmt_expr, context):
    from vyper.codegen.expr import Expr

    value, gas, skip_contract_check = None, None, None
    for kw in stmt_expr.keywords:
        if kw.arg == "gas":
            gas = Expr.parse_value_expr(kw.value, context)
        elif kw.arg == "value":
            value = Expr.parse_value_expr(kw.value, context)
        elif kw.arg == "skip_contract_check":
            skip_contract_check = kw.value.value
            assert isinstance(skip_contract_check, bool), "type checker missed this"
        else:
            raise TypeCheckFailure("Unexpected keyword argument")

    return value, gas, skip_contract_check


def ir_for_external_call(stmt_expr, context):
    from vyper.codegen.expr import Expr

    contract_address = Expr.parse_value_expr(stmt_expr.func.value, context)
    value, gas, skip_contract_check = _get_special_kwargs(stmt_expr, context)
    args_ir = [Expr(x, context).ir_node for x in stmt_expr.args]

    assert isinstance(contract_address.typ, InterfaceType)
    contract_name = contract_address.typ.name
    method_name = stmt_expr.func.attr
    contract_sig = context.sigs[contract_name][method_name]

    ret = _external_call_helper(
        contract_address,
        contract_sig,
        args_ir,
        context,
        value=value,
        gas=gas,
        skip_contract_check=skip_contract_check,
        expr=stmt_expr,
    )
    ret.annotation = stmt_expr.get("node_source_code")

    return ret
