from pxr import usd

def load_usd(file_path):
    try:
        stage = usd.Stage.Open(file_path)
    except Exception as e:
         raise Exception(f"Error opening USD file: {e}")

    for layer in stage.GetRootLayer().GetSubLayers():
        try:
           with open(layer.realPath, "r") as f:
                exec(f.read())
        except Exception as e:
            print(f"Error executing code from layer {layer.realPath}: {e}")

    return stage

try:
    stage = load_usd("path/to/malicious.usd")
except Exception as e:
    print(f"Error loading USD file: {e}")