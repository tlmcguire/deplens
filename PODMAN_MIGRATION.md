# Podman Migration Guide

This document outlines the migration from Docker to Podman for the DepLens project.

## Key Changes Made

### 1. Documentation Updates
- Updated `README.md` to reference Podman instead of Docker
- Changed installation links to point to Podman resources
- Updated all command examples to use `podman` instead of `docker`

### 2. Host Networking Changes
- Changed `host.docker.internal` to `host.containers.internal` in all configurations
- Updated `llmScan.py` OLLAMA_BASE_URL default to use the new hostname

### 3. Code Comments
- Updated build and run commands in source code comments
- Changed `interactiveGraph.py` and `dependencyTree.py` header comments

## Podman-Specific Considerations

### Host Networking
Podman uses `host.containers.internal` instead of `host.docker.internal` to access the host system from within containers. This affects:
- Ollama communication (port 11434)
- Any other host-based services

### Volume Mounting
Podman handles volume mounting similarly to Docker, but there are some differences:
- SELinux contexts may need to be considered on some systems
- Use `:Z` suffix for SELinux labeling if needed: `-v "$(pwd)/graphs:/graphs:Z"`

### Rootless vs Rootful
Podman can run in rootless mode (recommended for security):
- Rootless mode uses different port ranges (>1024)
- May require additional configuration for privileged operations

## Migration Command Equivalents

| Docker Command | Podman Equivalent |
|----------------|-------------------|
| `docker build -t deplens .` | `podman build -t deplens .` |
| `docker run --rm -it ...` | `podman run --rm -it ...` |
| `docker ps` | `podman ps` |
| `docker images` | `podman images` |
| `docker logs <container>` | `podman logs <container>` |

## Additional Podman Features

### Systemd Integration
Podman can generate systemd service files for containers:
```bash
podman generate systemd --name deplens --files
```

### Pod Support
Podman supports Kubernetes-style pods:
```bash
podman pod create --name deplens-pod -p 8080:8080
```

## Troubleshooting

### Common Issues
1. **Port binding errors**: Check if ports are available and not in use
2. **Permission issues**: Consider running in rootless mode
3. **Host connectivity**: Verify `host.containers.internal` is accessible

### Debugging Commands
```bash
# Check Podman version
podman version

# Check container logs
podman logs deplens

# Inspect container
podman inspect deplens

# Check running containers
podman ps -a
```

## Environment Variables

The following environment variables can be set to customize behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://host.containers.internal:11434` | Ollama server URL |
| `OLLAMA_PRIMARY_MODEL` | `llama3.1:8b` | Primary LLM model |
| `OLLAMA_FALLBACK_MODEL` | `gemma3:4b` | Fallback LLM model |
| `OLLAMA_MAX_RETRIES` | `3` | Maximum retry attempts |

## Testing the Migration

1. **Build the image**:
   ```bash
   podman build -t deplens .
   ```

2. **Run a test container**:
   ```bash
   podman run --rm -it -p 8080:8080 --add-host=host.containers.internal:host-gateway \
     -v "$(pwd)/graphs:/graphs" \
     -v "$(pwd)/models:/models" \
     -v "$(pwd)/results:/app/results" \
     deplens Django
   ```

3. **Verify functionality**:
   - Check web interface at http://localhost:8080
   - Test Ollama connectivity
   - Verify volume mounts work correctly
   - Test security analysis features

## Additional Resources

- [Podman Documentation](https://docs.podman.io/)
- [Podman Desktop](https://podman-desktop.io/)
- [Migrating from Docker to Podman](https://docs.podman.io/en/latest/markdown/podman-docker.1.html)
