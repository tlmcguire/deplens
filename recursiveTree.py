import ast
import builtins
import importlib.util
import sys
import os

def isBuiltinImport(moduleName):
    """Check if a module is a built-in module."""
    return moduleName in sys.builtin_module_names

def getLibraryFilePath(moduleName):
    """Retrieve the file path of a module."""
    try:
        spec = importlib.util.find_spec(moduleName)
        if spec and spec.origin:
            return spec.origin
    except ModuleNotFoundError:
        return None
    return None

def isStandardLibrary(moduleName):
    """Check if a module is part of the Python standard library."""
    libraryPath = getLibraryFilePath(moduleName)
    if libraryPath:
        # If the library path is within the base Python installation directory
        return libraryPath.startswith(sys.base_prefix)
    return False

class FunctionCallVisitor(ast.NodeVisitor):
    def __init__(self, imports, userDefined):
        self.imports = imports
        self.userDefined = userDefined
        self.calls = []
        self.visitedLibraries = set()  # Track visited libraries

    def visit_Call(self, node):
        """Process a function call."""
        callInfo = {"function": None, "origin": None, "args": [], "filePath": None}

        # Extract function name and module name if applicable
        if isinstance(node.func, ast.Name):
            # Direct function call (no module prefix)
            callInfo["function"] = node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Function call with module prefix, e.g., json.loads or re.match
            if isinstance(node.func.value, ast.Name):
                callInfo["function"] = f"{node.func.value.id}.{node.func.attr}"
            else:
                callInfo["function"] = node.func.attr

        # Store function call info
        self.calls.append(callInfo)
        self.generic_visit(node)

    def analyzeFunctionCalls(self):
        """Analyze all function calls and their origins."""
        for callInfo in self.calls:
            funcName = callInfo["function"]

            # Check if function is built-in
            if funcName in dir(builtins):
                callInfo["origin"] = "Built-in"

            # Check if function is user-defined
            elif funcName in self.userDefined:
                callInfo["origin"] = "User-defined"

            # Check if function belongs to an imported module
            elif funcName in self.imports:
                moduleName = self.imports[funcName]
                if isBuiltinImport(moduleName):
                    callInfo["origin"] = f"Built-in ({moduleName})"
                elif isStandardLibrary(moduleName):
                    callInfo["origin"] = f"Standard Library ({moduleName})"
                else:
                    callInfo["origin"] = f"Third-Party Library ({moduleName})"
                
                # Get file path for library functions and mark as visited
                callInfo["filePath"] = getLibraryFilePath(moduleName)
                if callInfo["filePath"] and moduleName not in self.visitedLibraries:
                    self.visitedLibraries.add(moduleName)  # Mark library as visited
            else:
                callInfo["origin"] = "Unknown"

            # Collect argument details
            callInfo["args"] = [ast.unparse(arg) for arg in callInfo["args"]] if hasattr(ast, "unparse") else []

def extractImports(tree):
    """Extract imported modules from the AST."""
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            for alias in node.names:
                imports[alias.name] = module
    return imports

def extractUserDefinedFunctions(tree):
    """Extract user-defined function names from the AST."""
    return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

def analyzePythonFile(filePath):
    """Analyze a Python file to extract function call information."""
    if not os.path.exists(filePath):
        print(f"Error: File '{filePath}' does not exist.")
        return

    with open(filePath, "r") as sourceFile:
        code = sourceFile.read()

    # Parse code
    tree = ast.parse(code)

    # Extract imports and user-defined functions
    imports = extractImports(tree)
    userDefined = extractUserDefinedFunctions(tree)

    # Visit AST nodes to analyze function calls
    visitor = FunctionCallVisitor(imports, userDefined)
    visitor.visit(tree)

    # Step 1: Print all function calls first
    print("Function Calls (before visiting libraries):")
    for i, call in enumerate(visitor.calls, 1):
        print(f"{i}: Function '{call['function']}'")
        print(f"   Arguments: {call['args']}")
    print()

    # Step 2: Now analyze and display information about the libraries
    visitor.analyzeFunctionCalls()

    # Step 3: Display detailed results, including library origins
    print("Function Call Analysis:")
    for i, call in enumerate(visitor.calls, 1):
        print(f"{i}: Function '{call['function']}'")
        print(f"   Origin: {call['origin']}")
        if call["filePath"]:
            print(f"   File Path: {call['filePath']}")
        if call["args"]:
            print(f"   Arguments: {call['args']}")
        print()

    # Display visited libraries
    print("Visited Libraries:")
    for library in visitor.visitedLibraries:
        print(f"- {library}")

if __name__ == "__main__":
    # Specify the file to analyze
    filePath = "./packages/ospyata/ospyata-3.1.4/ospyata-3.1.4/src/ospyata/osmata.py"
    analyzePythonFile(filePath)