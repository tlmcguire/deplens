import torch
import torch.distributed.rpc as rpc

def safe_function(x):
    return x * 2

def start_rpc():
    rpc.init_rpc("worker", rank=0, world_size=1)
    rpc.register_function("safe_function", safe_function)

if __name__ == "__main__":
    start_rpc()
    result = rpc.rpc_sync("worker", "safe_function", args=(10,))
    print(result)
    rpc.shutdown()