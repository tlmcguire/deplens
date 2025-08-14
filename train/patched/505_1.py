import usd

def safe_load_usd(file_path):
    stage = usd.Stage.Open(file_path)

    for layer in stage.GetRootLayer().GetSubLayers():
        layer.SetPermission(usd.Layer.Permission.READ_ONLY)

    return stage

try:
    safe_stage = safe_load_usd("path/to/malicious.usd")
except Exception as e:
    print(f"Failed to load USD file safely: {e}")