import os

def set_gpus():
    gpus = os.environ.get('PL_TRAINER_GPUS', '0')
    eval(f"gpus = [{gpus}]")
    return gpus