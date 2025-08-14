import os
import ast

def set_gpus():
    gpus = os.environ.get('PL_TRAINER_GPUS', '0')
    gpus = ast.literal_eval(f"[{gpus}]")
    return gpus