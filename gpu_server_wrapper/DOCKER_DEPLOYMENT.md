# Docker Container Deployment Guide

## Your Setup (Clarified)

```
┌─────────────────────────────────────────────────────────────────┐
│ GPU Host (192.168.200.205)                                      │
│                                                                  │
│  Docker Container (port 5964:5964 mapped)                       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Container Network: localhost                                │ │
│  │                                                              │ │
│  │  ┌─────────────────────────────────────────────┐            │ │
│  │  │ Ollama on ???                                │            │ │
│  │  │ (Need to verify where Ollama is running)    │            │ │
│  │  └─────────────────────────────────────────────┘            │ │
│  │                                                              │ │
│  │  ┌─────────────────────────────────────────────┐            │ │
│  │  │ Wrapper should run here                     │            │ │
│  │  │ Listen: 0.0.0.0:5965 (map to host:5965)    │            │ │
│  │  └─────────────────────────────────────────────┘            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## CRITICAL: Where is Ollama Running?

**Option 1: Ollama INSIDE Docker container**
```bash
# Inside container
curl http://localhost:5964/api/tags  # Should work
```
→ Wrapper connects to: `http://localhost:5964/api/chat`

**Option 2: Ollama OUTSIDE on GPU host**
```bash
# Inside container
curl http://localhost:5964/api/tags  # Won't work
curl http://172.17.0.1:5964/api/tags  # Might work (Docker bridge IP)
```
→ Wrapper connects to: `http://172.17.0.1:5964/api/chat` or `http://host.docker.internal:5964/api/chat`

## Step 1: Verify Ollama Location

**SSH into GPU host, then exec into container:**
```bash
# On GPU host
ssh stephen@192.168.200.205

# Enter the Docker container
docker exec -it $CTIDOCKER bash

# Inside container, try to find Ollama
curl http://localhost:5964/api/tags
```

**If it works:** Ollama is inside the container ✅
**If it fails:** Ollama is outside on the GPU host ❌

## Step 2: Copy Updated Wrapper File

**From your local Windows machine:**
```bash
cd C:\Users\steph\PycharmProjects\THF-Claude-Model

# Copy to GPU host first
scp gpu_server_wrapper/deepseek_wazuh_wrapper.py stephen@192.168.200.205:~/

# Then SSH and copy into container
ssh stephen@192.168.200.205
docker cp ~/deepseek_wazuh_wrapper.py $CTIDOCKER:/root/
```

## Step 3: Update Docker Port Mapping

Your current Docker container only maps port 5964. You need to also map 5965 for the wrapper.

**Option A: Restart container with new port mapping** (requires stopping)
```bash
# Stop and remove old container
docker stop $CTIDOCKER
docker rm $CTIDOCKER

# Start with BOTH ports mapped
docker run --init --name $CTIDOCKER -h $CTIDOCKER -d \
  -p 5964:5964 \
  -p 5965:5965 \
  --shm-size=64gb --gpus all --privileged \
  -v ~/cti-share:/host-share \
  nvidia/cuda:12.3.0-devel-ubuntu22.04 sleep infinity
```

**Option B: Use existing port 5964 for wrapper** (simpler, no restart)
```bash
# Change wrapper to listen on 5964
# Then stop Ollama temporarily, or use different architecture
```

## Recommended Approach: Use Port 5964 for Wrapper

Since you already have 5964 mapped, let's simplify:

**Architecture:**
```
Local THF (192.168.201.45)
  ↓
GPU Host:5964 → Container:5964 → Wrapper:5964
                                    ↓
                                  Ollama:11434 (inside container)
```

This requires Ollama to be on its **default port 11434** inside the container.

### Is Ollama on port 11434 or 5964 inside the container?

**Check inside container:**
```bash
docker exec -it $CTIDOCKER bash
ps aux | grep ollama
netstat -tlnp | grep ollama
```

## Step 4: Configuration Based on Ollama Location

### Scenario A: Ollama is on port 11434 (default) inside container

**Wrapper config:**
```python
OLLAMA_URL = "http://localhost:11434/api/chat"  # Correct!
port = 5964  # Listen on 5964 (already mapped)
```

**This might be your actual setup!** The old wrapper file had this config.

### Scenario B: Ollama is on port 5964 inside container

**Wrapper config:**
```python
OLLAMA_URL = "http://localhost:5964/api/chat"  # Use 5964
port = 5965  # Wrapper needs different port
```

But you need to add port mapping: `-p 5965:5965`

## Step 5: Create Correct Wrapper Configuration

Let me know the answer to this question:

**Inside the Docker container, what port is Ollama running on?**

Run this:
```bash
docker exec -it $CTIDOCKER bash -c "curl http://localhost:11434/api/tags"
docker exec -it $CTIDOCKER bash -c "curl http://localhost:5964/api/tags"
```

**Whichever one works**, that's the port Ollama is using.

## Temporary Quick Test

Let's test if the issue is just the port configuration:

**Create a simple test wrapper on port 5964:**

```bash
# SSH into GPU, then exec into container
ssh stephen@192.168.200.205
docker exec -it $CTIDOCKER bash

# Inside container, create test file
cat > /root/test_ollama.py << 'EOF'
import requests
import json

# Test both possible Ollama ports
for port in [11434, 5964]:
    try:
        url = f"http://localhost:{port}/api/tags"
        print(f"\nTrying {url}...")
        response = requests.get(url, timeout=5)
        print(f"✓ SUCCESS on port {port}")
        print(f"Response: {response.json()}")
        break
    except Exception as e:
        print(f"✗ FAILED on port {port}: {e}")
EOF

python3 test_ollama.py
```

This will tell us which port Ollama is actually on inside the container.

## Next Steps

Once you run the test above and tell me:
1. Which port Ollama is on inside the container (11434 or 5964)
2. Whether you can restart the Docker container (to add port 5965 mapping)

I'll provide the exact corrected configuration for your setup.

---

## Current Issue Summary

**Problem:** Your wrapper file is outdated (showing port 11434 and 5964 in logs)
**Need:**
1. Copy updated wrapper file into container
2. Verify Ollama port inside container
3. Decide on port strategy (use 5964 for wrapper, or add 5965 mapping)
