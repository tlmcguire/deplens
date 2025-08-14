import os

def execute_macro(macro_path):
    print(f"Executing macro from: {macro_path}")

def open_document_and_execute_macro(doc_path):
    macro_path = doc_path
    execute_macro(macro_path)

open_document_and_execute_macro('../some/unsafe/path/to/macro.py')