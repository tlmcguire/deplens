import sys
from tqdm import tqdm

def vulnerable_tqdm(iterable, **kwargs):
    for key, value in kwargs.items():
        if key in ['--delim', '--buf-size', '--manpath']:
            eval(value)
    return tqdm(iterable, **kwargs)

if __name__ == "__main__":
    for i in vulnerable_tqdm(range(10), desc="Processing", total=10, buf_size="os.system('echo Vulnerable!')"):
        pass