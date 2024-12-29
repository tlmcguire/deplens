# DepLens

DepLens is a containerized Python tool designed to assist in analyzing dependencies and modifying them for testing.

## Usage Guide
1. Specify the package to test by updating the `package` variable in `dependencyTree.py`
2. Specify the modifications to make in `dependencyTree.py`
3. Run `dependencyTree.py`

## AST Visualizer Usage

### Basic Usage
```bash
python astvisualizer.py -f your_file.py
```
### Command Line Arguments
`-f, --file`: Read Python code form specified file
`-l, --label`: Set custom label for visualization
`-n, --node-styles`: JSON string specifying node styles (e.g. shape, color, etc.)
`-e, --edge-styles`: JSON string specifying edge styles (e.g. color, dashed, solid, etc.)

Example:
```bash
python astvisualizer.py -f example.py \
  -l "Example AST" \
  -n '{"Module": {"shape": "hexagon"}}' \
  -e '{"Module.body": {"style": "dashed"}}'
```