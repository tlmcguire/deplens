import ast
import builtins
import importlib.util
import sys
import os
import sysconfig
from graphviz import Digraph

def isBuiltin(moduleName):
    """Returns True if a module is a built-in module."""
    return moduleName in sys.builtin_module_names

def isBuiltinImport(moduleName):
    """Returns True if a module is a built-in module."""
    return moduleName in sys.builtin_module_names

def getLibrarySpec(moduleName):
    """Returns the module's spec."""
    try:
        return importlib.util.find_spec(moduleName)
    except ModuleNotFoundError:
        return None

def getLibraryPath(moduleName):
    """Returns the path of a library."""
    spec = getLibrarySpec(moduleName)
    if spec and spec.origin:
        return spec.origin
    return None

def isStandardLibrary(moduleName):
    """Returns True if a module is part of the standard library."""
    spec = getLibrarySpec(moduleName)
    if spec is None:
        return False

    # Modules without __file__ are either built-in or standard library
    if spec.origin is None or not spec.has_location:
        return True

    # Normalize paths for comparison
    stdlib_paths = [os.path.normpath(sysconfig.get_path('stdlib'))]
    module_path = os.path.normpath(spec.origin)

    # Check if module_path is under any of the standard library paths
    return any(module_path.startswith(p) for p in stdlib_paths)

def getLibraryName(filePath, rootDir):
    """Determines the library name for a given file path."""
    # Normalize paths for comparison
    stdlib_paths = [os.path.normpath(sysconfig.get_path('stdlib'))]
    filePath = os.path.normpath(filePath)
    rootDir = os.path.normpath(rootDir)

    if filePath.startswith(rootDir):
        return os.path.basename(rootDir)
    elif any(filePath.startswith(p) for p in stdlib_paths):
        return 'Standard Library'
    elif 'site-packages' in filePath or 'dist-packages' in filePath:
        # Third-party libraries installed in site/dist-packages
        parts = filePath.split(os.sep)
        for dir_name in ['site-packages', 'dist-packages']:
            try:
                idx = parts.index(dir_name)
                if idx + 1 < len(parts):
                    return parts[idx + 1]
            except ValueError:
                continue
        return 'Third-Party Library'
    else:
        return 'Unknown'

class FunctionCallVisitor(ast.NodeVisitor):
    def __init__(self, imports, userDefined, fileLibraryMap, filePath, edges):
        self.imports = imports
        self.userDefined = userDefined
        self.visitedLibraries = set()
        self.fileLibraryMap = fileLibraryMap  # Map of file paths to library names
        self.currentFile = filePath
        self.edges = edges  # List to store edges

    def visit_Call(self, node):
        """Process a function call."""
        # Extract function name
        if isinstance(node.func, ast.Name):
            funcName = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_parts = []
            attr = node.func
            while isinstance(attr, ast.Attribute):
                func_parts.insert(0, attr.attr)
                attr = attr.value
            if isinstance(attr, ast.Name):
                func_parts.insert(0, attr.id)
            funcName = '.'.join(func_parts)
        else:
            # Handle other types of node.func, set a placeholder name
            funcName = "<unknown_function>"

        # Determine the library of the callee function
        callee_library = 'Unknown'
        if funcName in dir(builtins):
            callee_library = 'Built-in'
        elif funcName in self.userDefined:
            callee_library = self.fileLibraryMap.get(self.currentFile, 'User-defined')
        else:
            if funcName:
                parts = funcName.split('.')
            else:
                parts = []
            moduleName = None
            if parts and parts[0] in self.imports:
                moduleName = self.imports[parts[0]]
            elif parts and len(parts) > 1 and parts[0] in sys.modules:
                moduleName = parts[0]

            if moduleName and moduleName != "__main__":
                if isBuiltinImport(moduleName):
                    callee_library = f"Built-in ({moduleName})"
                elif isStandardLibrary(moduleName):
                    callee_library = 'Standard Library'
                else:
                    callee_library = f"Third-Party Library ({moduleName})"

                # Get file path for library functions and mark as visited
                libraryPath = getLibraryPath(moduleName)
                if libraryPath:
                    self.visitedLibraries.add(libraryPath)
                    self.fileLibraryMap[libraryPath] = callee_library
            else:
                callee_library = 'Unknown'

        # Add edge to the list if both nodes are valid
        caller_node = self.fileLibraryMap.get(self.currentFile, 'Unknown')
        callee_node = callee_library if callee_library != 'Unknown' else funcName

        if caller_node and callee_node:
            self.edges.add((caller_node, callee_node))

        self.generic_visit(node)

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
    return {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

def analyzePythonFile(filePath, rootDir, depth, maxDepth, analyzed_files, fileLibraryMap, edges):
    """Analyze a Python file to extract function call information."""
    if not os.path.exists(filePath):
        return

    if filePath in analyzed_files:
        return  # Avoid re-analyzing the same file

    analyzed_files.add(filePath)

    # Determine the library of the current file
    fileLibraryMap[filePath] = getLibraryName(filePath, rootDir)

    try:
        with open(filePath, "r", encoding="utf-8", errors="ignore") as sourceFile:
            code = sourceFile.read()
    except Exception:
        return

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return

    imports = extractImports(tree)
    userDefined = extractUserDefinedFunctions(tree)

    visitor = FunctionCallVisitor(imports, userDefined, fileLibraryMap, filePath, edges)
    visitor.visit(tree)

    if depth < maxDepth:
        for libFilePath in visitor.visitedLibraries:
            if libFilePath and libFilePath not in analyzed_files:
                if os.path.isfile(libFilePath):
                    analyzePythonFile(
                        libFilePath, rootDir, depth + 1, maxDepth, analyzed_files, fileLibraryMap, edges
                    )

def analyzeDirectory(directory, rootDir, depth, maxDepth, analyzed_files, fileLibraryMap, edges):
    """Recursively analyze Python files in a directory."""
    if depth > maxDepth:
        return
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                filePath = os.path.join(root, file)
                if filePath != os.path.abspath(__file__):  # Avoid analyzing the script itself
                    analyzePythonFile(filePath, rootDir, depth, maxDepth, analyzed_files, fileLibraryMap, edges)

if __name__ == "__main__":
    directory = "./packages/pytorch/"
    maxDepth = 4
    analyzed_files = set()
    fileLibraryMap = {}  # Map of file paths to library names
    edges = set()  # Set to store edges

    analyzeDirectory(directory, directory, 0, maxDepth, analyzed_files, fileLibraryMap, edges)

    # Create a new graph with clusters for each library
    new_graph = Digraph(comment='Call Graph')
    new_graph.attr(rankdir='TB')  # Set the graph direction to Top to Bottom
    new_graph.attr('node', shape='box')

    # Create subgraphs for each library
    libraries = set(fileLibraryMap.values())
    subgraphs = {}
    for lib in libraries:
        subg = Digraph(name=f'cluster_{lib}')
        subg.attr(label=lib)
        subg.attr(style='filled', color='lightgrey')
        subg.node_attr.update(style='filled', color='white')
        subgraphs[lib] = subg

    # Add nodes to subgraphs
    nodes_in_subgraphs = {}
    for filePath, lib in fileLibraryMap.items():
        node_name = lib
        if node_name not in nodes_in_subgraphs:
            subgraphs[lib].node(node_name)
            nodes_in_subgraphs[node_name] = lib

    # Add subgraphs to the main graph
    for subg in subgraphs.values():
        new_graph.subgraph(subg)

    # Add edges
    for src, dst in edges:
        new_graph.edge(src, dst)

    new_graph.render('call_graph', format='pdf', view=True)