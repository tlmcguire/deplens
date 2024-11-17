import ast
import builtins
import importlib.util
import sys
import os

def isBuiltin(moduleName):
    """Returns if a module is a built-in module."""
    return moduleName in sys.builtin_module_names

def getLibraryPath(moduleName):
    """Returns the path of a library."""
    try:
        spec = importlib.util.find_spec(moduleName)
        if spec is None:
            return None
        return spec.origin
    except ModuleNotFoundError:
        return None
    return None

def isStandardLibrary(moduleName):
    """Returns if a module is a standard library module."""
    libraryPath = getLibraryPath(moduleName)
    if libraryPath:
        # Check if the library is in the standard library
        return libraryPath.startswith(sys.base_prefix)
    return False

def isBuiltinImport(moduleName):
    """Returns if a module is a built-in import."""
    return moduleName in sys.builtin_module_names

def getLibraryFilePath(moduleName):
    """Returns the file path of a library."""
    try:
        spec = importlib.util.find_spec(moduleName)
        return spec.origin if spec else None
    except ModuleNotFoundError:
        return None

class FunctionCallVisitor(ast.NodeVisitor):
    def __init__(self, imports, userDefined):
        self.imports = imports
        self.userDefined = userDefined
        self.calls = []
        self.visitedLibraries = set()  # Libraries that have been visited

    def visit_Call(self, node):
        """Process a function call."""
        callInfo = {"function": None, "origin": None, "args": [], "filePath": None}

        # Extract function name and module name if applicable
        if isinstance(node.func, ast.Name):
            # Direct function call (no module prefix)
            callInfo["function"] = node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Function call with module prefix, e.g., json.loads or re.match
            func_parts = []
            attr = node.func
            while isinstance(attr, ast.Attribute):
                func_parts.insert(0, attr.attr)
                attr = attr.value
            if isinstance(attr, ast.Name):
                func_parts.insert(0, attr.id)
            callInfo["function"] = '.'.join(func_parts)

        # Collect argument details
        callInfo["args"] = [ast.unparse(arg) for arg in node.args] if hasattr(ast, "unparse") else []

        # Store function call info
        self.calls.append(callInfo)
        self.generic_visit(node)

    def analyzeOrigin(self):
        """Analyze function call origins."""
        for callInfo in self.calls:
            funcName = callInfo["function"]

            if not funcName:
                callInfo["origin"] = "Unknown"
                continue

            # Check if function is built-in
            if funcName in dir(builtins):
                callInfo["origin"] = "Built-in"

            # Check if function is user-defined
            elif funcName in self.userDefined:
                callInfo["origin"] = "User-defined"

            # Check if function belongs to an imported module
            else:
                parts = funcName.split('.')
                moduleName = None
                if parts[0] in self.imports:
                    moduleName = self.imports[parts[0]]
                elif len(parts) > 1 and parts[0] in sys.modules:
                    moduleName = parts[0]

                if moduleName:
                    if isBuiltinImport(moduleName):
                        callInfo["origin"] = f"Built-in ({moduleName})"
                    elif isStandardLibrary(moduleName):
                        callInfo["origin"] = f"Standard Library ({moduleName})"
                    else:
                        callInfo["origin"] = f"Third-Party Library ({moduleName})"

                    # Get file path for library functions and mark as visited
                    callInfo["filePath"] = getLibraryFilePath(moduleName)
                    if callInfo["filePath"]:
                        self.visitedLibraries.add(moduleName)  # Mark library as visited
                else:
                    callInfo["origin"] = "Unknown"

def extractImports(tree):
    """Extract imported modules from the AST."""
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            for alias in node.names:
                imports[alias.asname or alias.name] = module
    return imports

def extractUserDefinedFunctions(tree):
    """Extract user-defined function names from the AST."""
    return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

def analyzePythonFile(filePath, depth, maxDepth, analyzed_files):
    """Analyze a Python file to extract function call information."""
    if not os.path.exists(filePath):
        print(f"Error: File '{filePath}' does not exist.")
        return

    if filePath in analyzed_files:
        return  # Avoid re-analyzing the same file

    analyzed_files.add(filePath)

    try:
        with open(filePath, "r", encoding="utf-8", errors="ignore") as sourceFile:
            code = sourceFile.read()
    except Exception as e:
        print(f"Error reading file '{filePath}': {e}")
        return

    try:
        # Parse code
        tree = ast.parse(code)
    except SyntaxError as e:
        print(f"SyntaxError in file '{filePath}': {e}")
        return

    # Extract imports and user-defined functions
    imports = extractImports(tree)
    userDefined = extractUserDefinedFunctions(tree)

    # Visit AST nodes to analyze function calls
    visitor = FunctionCallVisitor(imports, userDefined)
    visitor.visit(tree)

    # Analyze and display information about the libraries
    visitor.analyzeOrigin()

    # Step 3: Display detailed results, including library origins
    print(f"\nFunction Call Analysis in {filePath}:")
    for i, call in enumerate(visitor.calls, 1):
        print(f"{i}: Function '{call['function']}'")
        print(f"   Origin: {call['origin']}")
        if call["filePath"]:
            print(f"   File Path: {call['filePath']}")
        if call["args"]:
            print(f"   Arguments: {call['args']}")
        print()

    # Recursively analyze libraries if depth limit is not reached
    if depth < maxDepth:
        for library in visitor.visitedLibraries:
            libraryPath = getLibraryFilePath(library)
            if libraryPath and os.path.isfile(libraryPath):
                analyzePythonFile(libraryPath, depth + 1, maxDepth, analyzed_files)
            elif libraryPath and os.path.isdir(os.path.dirname(libraryPath)):
                analyzeDirectory(os.path.dirname(libraryPath), depth + 1, maxDepth, analyzed_files)

def analyzeDirectory(directory, depth, maxDepth, analyzed_files):
    """Recursively analyze Python files in a directory."""
    print(f"Analyzing directory: {directory}")
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                filePath = os.path.join(root, file)
                analyzePythonFile(filePath, depth, maxDepth, analyzed_files)

if __name__ == "__main__":
    # Specify the directory to analyze and the maximum recursion depth
    directory = "./packages/ospyata/ospyata-3.1.4/ospyata-3.1.4/src/ospyata"
    maxDepth = 2
    analyzed_files = set()
    analyzeDirectory(directory, 0, maxDepth, analyzed_files)