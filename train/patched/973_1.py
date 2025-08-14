

@public
@constant
def safe_external_call(external_contract: address) -> bool:
    external_contract.call()

    return True