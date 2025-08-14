import os
import sys

def load_module(module_name):
    return __import__(module_name)

my_module = load_module('my_trojan_module')