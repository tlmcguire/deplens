

def set_storage_slots_with_overrides(
    vyper_module: vy_ast.Module, storage_layout_overrides: StorageLayout
) -> StorageLayout:
    """
    Parse module-level Vyper AST to calculate the layout of storage variables.
    Returns the layout as a dict of variable name -> variable info
    """

    ret: Dict[str, Dict] = {}
    reserved_slots = StorageAllocator()

    for node in vyper_module.get_children(vy_ast.FunctionDef):
        type_ = node._metadata["type"]

        if type_.nonreentrant is None:
            continue

        variable_name = f"nonreentrant.{type_.nonreentrant}"

        if variable_name in ret:
            _slot = ret[variable_name]["slot"]
            type_.set_reentrancy_key_position(StorageSlot(_slot))
            continue

        if variable_name in storage_layout_overrides:
            layout = storage_layout_overrides[variable_name]
            if not isinstance(layout, dict) or "slot" not in layout:
                 raise StorageLayoutException(
                    f"Invalid storage layout override for {variable_name}. "
                    "Expected a dictionary with a 'slot' key.",
                    node,
                )
            reentrant_slot = layout["slot"]
            if not isinstance(reentrant_slot, int):
                 raise StorageLayoutException(
                    f"Invalid storage slot for {variable_name}. "
                    "Expected an int.",
                    node,
                )
            reserved_slots.reserve_slot_range(reentrant_slot, 1, variable_name)

            type_.set_reentrancy_key_position(StorageSlot(reentrant_slot))

            ret[variable_name] = {"type": "nonreentrant lock", "slot": reentrant_slot}
        else:
            raise StorageLayoutException(
                f"Could not find storage_slot for {variable_name}. "
                "Have you used the correct storage layout file?",
                node,
            )

    for node in vyper_module.get_children(vy_ast.VariableDecl):
        if node.get("annotation.func.id") == "immutable":
            continue

        varinfo = node.target._metadata["varinfo"]

        if node.target.id in storage_layout_overrides:
            layout = storage_layout_overrides[node.target.id]
            if not isinstance(layout, dict) or "slot" not in layout:
                 raise StorageLayoutException(
                    f"Invalid storage layout override for {node.target.id}. "
                    "Expected a dictionary with a 'slot' key.",
                    node,
                )
            var_slot = layout["slot"]
            if not isinstance(var_slot, int):
                 raise StorageLayoutException(
                    f"Invalid storage slot for {node.target.id}. "
                    "Expected an int.",
                    node,
                )
            if var_slot < 0 or var_slot >= 2**256:
                raise StorageLayoutException(
                    f"Storageslot for {node.target.id} out of bounds: {var_slot}.",
                    node,
                )
            storage_length = varinfo.typ.storage_size_in_words
            try:
                reserved_slots.reserve_slot_range(var_slot, storage_length, node.target.id)
            except StorageLayoutException as e:
                e.node = node
                raise e
            varinfo.set_position(StorageSlot(var_slot))

            ret[node.target.id] = {"type": str(varinfo.typ), "slot": var_slot}
        else:
            raise StorageLayoutException(
                f"Could not find storage_slot for {node.target.id}. "
                "Have you used the correct storage layout file?",
                node,
            )

    return ret


def set_storage_slots(vyper_module: vy_ast.Module) -> StorageLayout:
    """
    Parse module-level Vyper AST to calculate the layout of storage variables.
    Returns the layout as a dict of variable name -> variable info
    """

    allocator = SimpleStorageAllocator()

    ret: Dict[str, Dict] = {}

    for node in vyper_module.get_children(vy_ast.FunctionDef):
        type_ = node._metadata["type"]
        if type_.nonreentrant is None:
            continue

        variable_name = f"nonreentrant.{type_.nonreentrant}"

        if variable_name in ret:
            _slot = ret[variable_name]["slot"]
            type_.set_reentrancy_key_position(StorageSlot(_slot))
            continue

        slot = allocator.allocate_slot(1, variable_name)

        type_.set_reentrancy_key_position(StorageSlot(slot))

        ret[variable_name] = {"type": "nonreentrant lock", "slot": slot}


    for node in vyper_module.get_children(vy_ast.VariableDecl):
        if node.is_constant or node.is_immutable:
            continue

        varinfo = node.target._metadata["varinfo"]
        type_ = varinfo.typ

        n_slots = type_.storage_size_in_words
        try:
            slot = allocator.allocate_slot(n_slots, node.target.id)
        except StorageLayoutException as e:
            e.node = node
            raise e

        varinfo.set_position(StorageSlot(slot))

        ret[node.target.id] = {"type": str(type_), "slot": slot}

    return ret