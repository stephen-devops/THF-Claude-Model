# DeepSeek Wrapper - Quick Start Guide

## Problem Statement

**Issue:** DeepSeek-R1 was giving generic SQL/Splunk advice instead of calling Wazuh tools when queried directly.

**Root Cause:** DeepSeek-R1's `<think>` reasoning traces interfere with LangChain's ReAct parser, and the system prompt from the THF app wasn't strong enough.

**Solution:** Custom Flask wrapper that injects a strong Wazuh-specific system prompt and parses DeepSeek's response format.

---

## Files Overview

| File | Purpose |
|------|---------|
| `deepseek_wazuh_wrapper.py` | Main Flask wrapper (deploy to GPU server) |
| `requirements.txt` | Python dependencies |
| `deepseek-wrapper.service` | Systemd service file for auto-start |
| `test_wrapper.py` | Test suite (run from local machine) |
| `DEPLOYMENT_CHECKLIST.md` | Step-by-step deployment checklist ✅ |
| `README_DEPLOYMENT.md` | Comprehensive deployment guide |
| `PORT_CONFIGURATION.md` | Port architecture explanation |
| `QUICK_START.md` | This file |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Local Machine (192.168.201.45)                         │
│                                                         │
│  THF Application                                        │
│  └─> LOCAL_MODEL_URL=http://192.168.200.205:5965      │
│                                                         │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP POST /api/chat
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ GPU Server (192.168.200.205)                           │
│                                                         │
│  ┌────────────────────────────────────────────┐        │
│  │ PORT 5965 - Wrapper (NEW)                  │        │
│  │ deepseek_wazuh_wrapper.py                  │        │
│  │                                             │        │
│  │ ✓ Injects Wazuh system prompt              │        │
│  │ ✓ Strips <think> tags                       │        │
│  │ ✓ Returns OpenAI-compatible JSON           │        │
│  └────────────┬───────────────────────────────┘        │
│               │                                         │
│               ▼                                         │
│  ┌────────────────────────────────────────────┐        │
│  │ PORT 5964 - Ollama (EXISTING)              │        │
│  │ Runs: deepseek-r1:32b                      │        │
│  └────────────────────────────────────────────┘        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 3-Minute Deployment

### Step 1: Copy files to GPU server (from Windows)

```bash
cd C:\Users\steph\PycharmProjects\THF-Claude-Model
scp gpu_server_wrapper/deepseek_wazuh_wrapper.py stephen@192.168.200.205:~/
scp gpu_server_wrapper/requirements.txt stephen@192.168.200.205:~/
scp gpu_server_wrapper/deepseek-wrapper.service stephen@192.168.200.205:~/
```

### Step 2: Install and test on GPU server

```bash
ssh stephen@192.168.200.205

# Install dependencies
pip3 install flask requests

# Test manually first (IMPORTANT!)
python3 ~/deepseek_wazuh_wrapper.py

# Should see:
# Starting DeepSeek-R1 Wazuh Wrapper
# Listening on: 0.0.0.0:5965
```

### Step 3: Test from local machine (new terminal)

```bash
# Test health
curl http://192.168.200.205:5965/health

# Run full test suite
cd C:\Users\steph\PycharmProjects\THF-Claude-Model
python gpu_server_wrapper/test_wrapper.py
```

**Critical:** Test 4 (Tool Calling) must PASS before proceeding!

### Step 4: Set up as service (on GPU server)

```bash
sudo cp ~/deepseek-wrapper.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable deepseek-wrapper
sudo systemctl start deepseek-wrapper
sudo systemctl status deepseek-wrapper
```

### Step 5: Update THF configuration (local machine)

Edit `.env`:
```env
FORCE_MODEL=none  # Enable routing
LOCAL_MODEL_URL=http://192.168.200.205:5965
```

### Step 6: Restart THF and test

```bash
# Restart THF app
uvicorn main:app --host 0.0.0.0 --port 8000

# Open UI: http://localhost:8501
# Try: "Count alerts by rule group for the last 24 hours"
```

---

## Success Criteria

✅ **All must be true:**

1. Wrapper service running: `sudo systemctl status deepseek-wrapper`
2. Health check passes: `curl http://192.168.200.205:5965/health`
3. Test suite passes: `python gpu_server_wrapper/test_wrapper.py` (4/4 tests)
4. THF logs show: `Model routing decision: selected_model=deepseek`
5. DeepSeek response contains: `Action: analyze_alerts`
6. Actual Wazuh data returned (not generic SQL advice)

---

## Monitoring Commands

```bash
# GPU server logs
ssh stephen@192.168.200.205
sudo journalctl -u deepseek-wrapper -f

# Local machine
# Watch uvicorn output for routing decisions
```

---

## Troubleshooting

### If Test 4 (Tool Calling) fails:

```bash
# Check wrapper logs
sudo journalctl -u deepseek-wrapper -n 50

# Look for "Answer preview" - does it contain "Action:"?
```

**If still giving generic advice:**
- System prompt may need strengthening
- Add more few-shot examples
- Consider adjusting DeepSeek parameters

### If connection fails:

```bash
# Check firewall
sudo ufw allow 5965/tcp

# Check Ollama
curl http://localhost:5964/api/tags

# Check wrapper
sudo systemctl status deepseek-wrapper
```

---

## Rollback Plan

If wrapper doesn't work, revert to Claude-only:

```bash
# GPU server
sudo systemctl stop deepseek-wrapper

# Local machine .env
FORCE_MODEL=claude

# Restart THF app
```

Everything will work exactly as before.

---

## Key Configuration Values

| Setting | Value | Location |
|---------|-------|----------|
| Ollama Port | 5964 | GPU server (existing) |
| Wrapper Port | 5965 | GPU server (new) |
| Local Model URL | http://192.168.200.205:5965 | .env on local machine |
| DeepSeek Model | deepseek-r1:32b | Ollama on GPU |
| Complexity Threshold | 0.6 | .env `COMPLEXITY_THRESHOLD` |

---

## What the Wrapper Does

1. **Receives** query from THF app
2. **Injects** comprehensive Wazuh system prompt with:
   - Tool descriptions (8 tools)
   - ReAct format instructions
   - Few-shot examples of correct tool usage
3. **Forwards** to Ollama DeepSeek-R1 on port 5964
4. **Parses** response (extracts `<think>` tags)
5. **Returns** clean ReAct-formatted answer to THF app

---

## Expected Behavior Change

### Before (Direct Ollama):
```
Query: "Count alerts by rule group for the last 24 hours"

DeepSeek Response:
"You can use Splunk with this query: index=wazuh | stats count by rule.groups..."
❌ Generic advice, no tool execution
```

### After (With Wrapper):
```
Query: "Count alerts by rule group for the last 24 hours"

DeepSeek Response:
"Action: analyze_alerts
Action Input: {"action": "count_by_field", "field": "rule.groups", "time_range": "24h"}"
✅ Proper tool calling, real data returned
```

---

## Next Steps After Deployment

1. ✅ Deploy wrapper following this guide
2. ✅ Verify Test 4 passes (tool calling works)
3. Monitor for 1 day with FORCE_MODEL=none (hybrid mode)
4. Review logs for any failures
5. Compare response quality: DeepSeek vs Claude
6. Gradually increase DeepSeek traffic if successful

---

## Performance Expectations

- **Simple queries** (complexity < 0.6): DeepSeek (~30-60 seconds)
- **Complex queries** (complexity ≥ 0.6): Claude (~10-20 seconds)
- **Cost savings**: ~70% (assuming 70% of queries are simple)
- **Fallback**: Automatic to Claude if DeepSeek fails

---

## Questions?

Refer to detailed documentation:
- **Deployment steps**: `DEPLOYMENT_CHECKLIST.md`
- **Port architecture**: `PORT_CONFIGURATION.md`
- **Full guide**: `README_DEPLOYMENT.md`

Good luck! 🚀
