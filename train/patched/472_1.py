import os
import sys

def load_plugin(plugin_name):
    safe_plugin_dir = os.path.join(os.getcwd(), 'plugins')

    if not os.path.isdir(safe_plugin_dir):
        print("Plugin directory does not exist.")
        return None

    plugin_path = os.path.join(safe_plugin_dir, f"{plugin_name}.py")
    if not os.path.isfile(plugin_path):
        print(f"Plugin {plugin_name} does not exist in the safe directory.")
        return None

    sys.path.append(safe_plugin_dir)

    try:
        plugin = __import__(plugin_name)
        return plugin
    except ImportError:
        print(f"Failed to load plugin: {plugin_name}")

plugin_name = 'safe_plugin'
load_plugin(plugin_name)