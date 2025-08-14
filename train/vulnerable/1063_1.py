def unsafe_external_call(target_contract, input_data):
    return_data = target_contract.call(input_data)

    if len(return_data) < expected_minimum_size:
        return_data = None

    process_return_data(return_data)

def process_return_data(return_data):
    if return_data is not None:
        pass