import os
import sys

def load_plugin(plugin_name):
    sys.path.append(os.path.join(os.getcwd(), 'plugins'))

    try:
        plugin = __import__(plugin_name)
        return plugin
    except ImportError:
        print(f"Failed to load plugin: {plugin_name}")

plugin_name = 'malicious_plugin'
load_plugin(plugin_name)