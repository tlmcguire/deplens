import torch
import torch.distributed.rpc as rpc

def vulnerable_function(code):
    return eval(code)

def start_rpc():
    rpc.init_rpc("worker", rank=0, world_size=1)
    rpc.register_function("vulnerable_function", vulnerable_function)

if __name__ == "__main__":
    start_rpc()
    result = rpc.rpc_sync("worker", "vulnerable_function", args=("print('Executing arbitrary code!')",))
    print(result)
    rpc.shutdown()