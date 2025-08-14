@public
def safe_deploy_from_blueprint(salt: uint256):
    cached_salt: uint256 = salt

    assert not is_contract(my_blueprint)


    create_from_blueprint(my_blueprint, cached_salt)
