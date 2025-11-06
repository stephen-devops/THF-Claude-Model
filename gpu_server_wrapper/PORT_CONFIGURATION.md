# Port Configuration Summary

## Complete Network Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ LOCAL MACHINE (192.168.201.45)                                     │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ THF Application (FastAPI + Streamlit)                         │ │
│  │                                                                │ │
│  │ Environment Variable:                                          │ │
│  │ LOCAL_MODEL_URL=http://192.168.200.205:5965                   │ │
│  │                                                                │ │
│  │ Makes HTTP requests to: 192.168.200.205:5965                  │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              │ HTTP Request
                              │ (POST /api/chat with user query)
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ GPU SERVER (192.168.200.205)                                       │
│                                                                     │
│  ┌────────────────────────────────────────────────────┐            │
│  │ PORT 5965 (NEW - Wrapper Layer)                   │            │
│  │ ───────────────────────────────────────────────────│            │
│  │ deepseek_wazuh_wrapper.py (Flask)                  │            │
│  │                                                     │            │
│  │ Listens on: 0.0.0.0:5965 (external access)        │            │
│  │                                                     │            │
│  │ What it does:                                      │            │
│  │ ✓ Receives requests from THF app                   │            │
│  │ ✓ Injects Wazuh system prompt                      │            │
│  │ ✓ Formats for DeepSeek-R1                          │            │
│  │ ✓ Forwards to Ollama on port 5964                 │            │
│  │ ✓ Parses DeepSeek response                         │            │
│  │ ✓ Strips <think> tags                              │            │
│  │ ✓ Returns OpenAI-compatible JSON                   │            │
│  └──────────────────────┬─────────────────────────────┘            │
│                         │                                           │
│                         │ Internal HTTP Request                     │
│                         │ (to localhost:5964)                       │
│                         │                                           │
│                         ▼                                           │
│  ┌────────────────────────────────────────────────────┐            │
│  │ PORT 5964 (EXISTING - Ollama)                     │            │
│  │ ───────────────────────────────────────────────────│            │
│  │ Ollama Server                                      │            │
│  │                                                     │            │
│  │ Listens on: 0.0.0.0:5964                          │            │
│  │ (You configured this earlier)                      │            │
│  │                                                     │            │
│  │ What it does:                                      │            │
│  │ ✓ Runs DeepSeek-R1:32b model                       │            │
│  │ ✓ Generates responses                              │            │
│  │ ✓ Returns to wrapper on port 5965                 │            │
│  └────────────────────────────────────────────────────┘            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Port Summary Table

| Port | Service | Listens On | Accessible From | Purpose |
|------|---------|------------|-----------------|---------|
| **5965** | Wrapper (Flask) | 0.0.0.0:5965 | External (local machine) | Custom API with Wazuh prompts |
| **5964** | Ollama | 0.0.0.0:5964 | External (local machine) + Wrapper | Native DeepSeek-R1 inference |

## Why Two Ports?

### Before (Direct Connection - What You Tested Earlier):
```
THF App → Port 5964 (Ollama) → DeepSeek-R1
```
**Problem:** No control over system prompts, DeepSeek gave generic advice

### After (With Wrapper - New Setup):
```
THF App → Port 5965 (Wrapper) → Port 5964 (Ollama) → DeepSeek-R1
```
**Solution:** Wrapper injects proper Wazuh system prompts

## Configuration Files

### On GPU Server (`deepseek_wazuh_wrapper.py`):
```python
OLLAMA_URL = "http://localhost:5964/api/chat"  # Wrapper → Ollama

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5965,  # Wrapper listens here
        ...
    )
```

### On Local Machine (`.env`):
```bash
LOCAL_MODEL_URL=http://192.168.200.205:5965  # THF → Wrapper
```

## Traffic Flow Example

**User Query:** "Count alerts by rule group for the last 24 hours"

### Step-by-Step:
1. **THF App** sends HTTP POST to `192.168.200.205:5965`
2. **Wrapper (port 5965)** receives request
3. **Wrapper** injects system prompt about Wazuh tools
4. **Wrapper** sends to `localhost:5964` (Ollama)
5. **Ollama (port 5964)** processes with DeepSeek-R1
6. **Ollama** returns response with `<think>` tags
7. **Wrapper** parses and cleans response
8. **Wrapper** returns to THF app on local machine
9. **THF App** receives clean ReAct-formatted response

## Firewall Configuration

On GPU server, ensure both ports are accessible:

```bash
# Check firewall status
sudo ufw status

# Allow wrapper port (new)
sudo ufw allow 5965/tcp

# Port 5964 should already be open from earlier setup
# If not:
sudo ufw allow 5964/tcp
```

## Testing Each Layer

### Test Ollama directly (port 5964):
```bash
curl http://192.168.200.205:5964/api/tags
```

### Test Wrapper (port 5965):
```bash
curl http://192.168.200.205:5965/health
```

### Test full integration:
```bash
python gpu_server_wrapper/test_wrapper.py
```

## Common Mistakes to Avoid

❌ **Wrong:** Pointing THF to port 5964 (bypasses wrapper)
```env
LOCAL_MODEL_URL=http://192.168.200.205:5964  # Don't do this!
```

✅ **Correct:** Pointing THF to port 5965 (uses wrapper)
```env
LOCAL_MODEL_URL=http://192.168.200.205:5965  # Do this!
```

❌ **Wrong:** Wrapper trying to connect to port 11434 (default Ollama port)
```python
OLLAMA_URL = "http://localhost:11434/api/chat"  # Won't work on your setup
```

✅ **Correct:** Wrapper connecting to your Ollama port 5964
```python
OLLAMA_URL = "http://localhost:5964/api/chat"  # Correct for your setup
```

## Quick Reference Commands

### On GPU Server:
```bash
# Start wrapper manually (testing)
python3 deepseek_wazuh_wrapper.py

# Start as service (production)
sudo systemctl start deepseek-wrapper

# View wrapper logs
sudo journalctl -u deepseek-wrapper -f

# Check Ollama
ollama list
curl http://localhost:5964/api/tags
```

### On Local Machine:
```bash
# Test connectivity
curl http://192.168.200.205:5965/health

# Run test suite
python gpu_server_wrapper/test_wrapper.py

# Restart THF app
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Rollback to Direct Ollama (If Needed)

If wrapper doesn't work, you can revert:

```bash
# On GPU server: Stop wrapper
sudo systemctl stop deepseek-wrapper

# On local machine: Point directly to Ollama
# Edit .env:
LOCAL_MODEL_URL=http://192.168.200.205:5964
```

But you lose the custom system prompt injection!
