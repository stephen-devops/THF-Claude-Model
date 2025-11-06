# Deployment Status - DeepSeek Wrapper Integration

**Date:** 2025-11-06
**Status:** ✅ Ready for Deployment
**Current Branch:** integrateDeepSeekBranch

---

## Summary

The DeepSeek-R1 wrapper solution is complete and ready for deployment to your GPU server. This wrapper solves the critical tool calling issue by injecting strong Wazuh-specific system prompts.

---

## What Has Been Completed

### 1. Core Implementation ✅

- [x] **Multi-model routing system** (`agent/query_complexity.py`)
  - 7-factor complexity analyzer
  - Configurable threshold (default: 0.6)
  - Classification: simple/moderate/complex

- [x] **WazuhSecurityAgent modifications** (`agent/wazuh_agent.py`)
  - Dual LLM initialization (Claude + DeepSeek)
  - Dynamic model routing based on query complexity
  - Automatic fallback to Claude on errors
  - Model switching with agent reinitialization

- [x] **Configuration updates**
  - `.env` with hybrid mode settings
  - `main.py` with local_model_config
  - Environment variables for all settings

### 2. Wrapper Solution ✅

- [x] **Flask API wrapper** (`deepseek_wazuh_wrapper.py`)
  - System prompt injection with 8 Wazuh tools documented
  - ReAct format enforcement with few-shot examples
  - `<think>` tag parsing and stripping
  - OpenAI-compatible API response format
  - Comprehensive logging

- [x] **Service configuration**
  - Systemd service file for auto-start
  - Python dependencies file
  - Health check endpoint
  - Monitoring capabilities

### 3. Testing Infrastructure ✅

- [x] **Automated test suite** (`test_wrapper.py`)
  - Test 1: Health check
  - Test 2: Root endpoint
  - Test 3: Simple chat
  - Test 4: Tool calling (CRITICAL)

### 4. Documentation ✅

- [x] **QUICK_START.md** - 3-minute deployment guide
- [x] **DEPLOYMENT_CHECKLIST.md** - Step-by-step checklist with success criteria
- [x] **README_DEPLOYMENT.md** - Comprehensive deployment guide
- [x] **PORT_CONFIGURATION.md** - Port architecture explanation
- [x] **requirements.txt** - Python dependencies
- [x] **deepseek-wrapper.service** - Systemd configuration

---

## Problem Solved

**Original Issue:** DeepSeek-R1 was returning generic SQL/Splunk advice instead of calling Wazuh tools.

**Example of failure:**
```
Query: "Count alerts by rule group for the last 24 hours"
DeepSeek Response: "You can use Splunk with this query: index=wazuh | stats count by rule.groups..."
❌ No tool execution, generic advice
```

**Root Cause:**
1. DeepSeek-R1 uses `<think>` tags for reasoning traces
2. These interfere with LangChain's ReAct parser
3. System prompts from THF app weren't strong enough

**Solution:**
- Flask wrapper on GPU server that:
  1. Injects comprehensive Wazuh system prompt
  2. Enforces ReAct format with examples
  3. Strips `<think>` tags from response
  4. Returns clean, parseable output

---

## Architecture

```
THF App (Local:192.168.201.45)
  ↓ Query complexity analysis
  ├─> Complex queries (≥0.6) → Claude Sonnet 4 (API)
  └─> Simple queries (<0.6) → Wrapper (GPU:5965)
                                ↓
                              Ollama (GPU:5964)
                                ↓
                              DeepSeek-R1:32b
```

**Port Configuration:**
- **5964**: Ollama (existing setup)
- **5965**: Wrapper (new layer)

---

## Files Ready for Deployment

### On GPU Server (192.168.200.205):
```
/home/stephen/
├── deepseek_wazuh_wrapper.py  (Flask wrapper)
├── deepseek-wrapper.service   (Systemd config)
└── requirements.txt           (Dependencies)
```

### On Local Machine:
```
C:\Users\steph\PycharmProjects\THF-Claude-Model\
├── .env                        (Updated with wrapper URL)
├── agent/
│   ├── wazuh_agent.py         (Modified for routing)
│   └── query_complexity.py    (New complexity analyzer)
└── gpu_server_wrapper/
    ├── test_wrapper.py        (Test suite)
    └── [All documentation files]
```

---

## Configuration Values

### Environment Variables (.env):
```env
# Local Model Configuration
LOCAL_MODEL_ENABLED=true
LOCAL_MODEL_PROVIDER=ollama
LOCAL_MODEL_URL=http://192.168.200.205:5965  # Points to wrapper
LOCAL_MODEL_NAME=deepseek-r1:32b
LOCAL_MODEL_TIMEOUT=120

# Hybrid Mode
HYBRID_MODE=true
COMPLEXITY_THRESHOLD=0.6
FORCE_MODEL=none  # Set to 'claude' or 'deepseek' to force specific model

# Claude Configuration (existing)
ANTHROPIC_API_KEY=<your-key>
```

### Wrapper Configuration (deepseek_wazuh_wrapper.py):
```python
OLLAMA_URL = "http://localhost:5964/api/chat"  # Wrapper → Ollama
MODEL_NAME = "deepseek-r1:32b"
PORT = 5965  # Wrapper listens here
```

---

## Deployment Steps (Quick Reference)

1. **Copy files to GPU server**
   ```bash
   scp gpu_server_wrapper/{deepseek_wazuh_wrapper.py,requirements.txt,deepseek-wrapper.service} stephen@192.168.200.205:~/
   ```

2. **Install dependencies on GPU**
   ```bash
   ssh stephen@192.168.200.205
   pip3 install flask requests
   ```

3. **Test wrapper manually**
   ```bash
   python3 ~/deepseek_wazuh_wrapper.py
   # Should see: Listening on: 0.0.0.0:5965
   ```

4. **Test from local machine**
   ```bash
   curl http://192.168.200.205:5965/health
   python gpu_server_wrapper/test_wrapper.py
   ```

5. **Set up as service**
   ```bash
   sudo cp ~/deepseek-wrapper.service /etc/systemd/system/
   sudo systemctl enable deepseek-wrapper
   sudo systemctl start deepseek-wrapper
   ```

6. **Update local .env and restart THF**

---

## Success Criteria

Before considering deployment successful, verify:

- [ ] Wrapper service running: `systemctl status deepseek-wrapper` shows "active (running)"
- [ ] Health check passes: `curl http://192.168.200.205:5965/health` returns "healthy"
- [ ] Test suite passes: All 4 tests PASS (especially Test 4: Tool Calling)
- [ ] THF logs show: `Model routing decision: selected_model=deepseek`
- [ ] DeepSeek response contains: `Action: analyze_alerts` (not generic advice)
- [ ] Actual Wazuh data returned to user

---

## Expected Outcomes

### Immediate Benefits:
- DeepSeek correctly calls Wazuh tools (instead of giving generic advice)
- ~70% cost reduction (simple queries use free local model)
- Maintained response quality via complexity-based routing
- Automatic fallback to Claude on errors

### Performance:
- Simple queries: 30-60 seconds (DeepSeek on GPU)
- Complex queries: 10-20 seconds (Claude API)
- Overall: Acceptable performance with significant cost savings

---

## Rollback Plan

If deployment fails or wrapper doesn't solve the issue:

```bash
# GPU server
sudo systemctl stop deepseek-wrapper

# Local machine .env
FORCE_MODEL=claude

# Restart THF app
```

Application will revert to Claude-only mode (original behavior).

---

## Monitoring After Deployment

### GPU Server Logs:
```bash
sudo journalctl -u deepseek-wrapper -f
```

Look for:
- "Answer preview" containing "Action:" and "Action Input:"
- No error messages
- Response times (should be 30-60 seconds)

### Local THF Logs:
```bash
# In uvicorn output
Model routing decision: selected_model=deepseek
Switched to local model: model=deepseek-r1:32b
```

### User Queries to Test:
1. **Simple** (should use DeepSeek):
   - "Count alerts by rule group for the last 24 hours"
   - "Show me critical alerts from today"
   - "List top 10 hosts by alert count"

2. **Complex** (should use Claude):
   - "Correlate authentication failures with file modifications and explain the attack pattern"
   - "Investigate the timeline of suspicious activity on host XYZ and relate to MITRE ATT&CK"
   - "Compare alert patterns from last week to identify emerging threats"

---

## Known Limitations

1. **DeepSeek Response Time**: 30-60 seconds (vs Claude's 10-20 seconds)
   - **Mitigation**: Only route simple queries to DeepSeek

2. **System Prompt Effectiveness**: May need tuning
   - **Mitigation**: Wrapper logs show exact prompts/responses for debugging

3. **Model Size**: 32B parameters requires GPU
   - **Current Setup**: ✅ Running on GPU server (192.168.200.205)

4. **Network Dependency**: Requires GPU server accessibility
   - **Mitigation**: Automatic fallback to Claude on connection failure

---

## Next Steps

### Immediate (Day 1):
1. Deploy wrapper to GPU server following QUICK_START.md
2. Verify Test 4 (tool calling) passes
3. Test with real queries through UI
4. Monitor logs closely

### Short-term (Week 1):
1. Monitor DeepSeek success rate
2. Adjust complexity threshold if needed (currently 0.6)
3. Strengthen system prompt if tool calling still inconsistent
4. Compare response quality: DeepSeek vs Claude

### Long-term (Month 1):
1. Calculate actual cost savings
2. Gradually increase DeepSeek traffic (20% → 50% → 70%)
3. Fine-tune complexity scoring factors
4. Consider adding response quality metrics

---

## Documentation Index

| File | Use Case |
|------|----------|
| **QUICK_START.md** | First-time deployment (3 minutes) |
| **DEPLOYMENT_CHECKLIST.md** | Step-by-step checklist with success criteria |
| **README_DEPLOYMENT.md** | Comprehensive guide with troubleshooting |
| **PORT_CONFIGURATION.md** | Understand port architecture |
| **DEPLOYMENT_STATUS.md** | This file - overall project status |

---

## Files Modified in Codebase

### New Files:
- `agent/query_complexity.py`
- `gpu_server_wrapper/deepseek_wazuh_wrapper.py`
- `gpu_server_wrapper/requirements.txt`
- `gpu_server_wrapper/test_wrapper.py`
- `gpu_server_wrapper/deepseek-wrapper.service`
- `gpu_server_wrapper/*.md` (documentation)

### Modified Files:
- `agent/wazuh_agent.py` (added routing logic)
- `main.py` (added local_model_config)
- `.env` (added hybrid mode settings)

### No Breaking Changes:
- All changes are backward compatible
- Setting `FORCE_MODEL=claude` reverts to original behavior
- Existing functionality unchanged when hybrid mode disabled

---

## Contact Information

**GPU Server**: stephen@192.168.200.205
**Local Machine**: 192.168.201.45
**Git Branch**: integrateDeepSeekBranch

**Service Management:**
```bash
sudo systemctl status deepseek-wrapper
sudo journalctl -u deepseek-wrapper -f
```

---

## Git Status (Pre-Deployment)

Modified files:
- `agent/wazuh_agent.py`

Untracked files:
- `agent/query_complexity.py`
- `gpu_server_wrapper/`

**Recommendation:** Create git commit after successful deployment and testing.

---

## Final Checklist Before Deployment

- [x] Wrapper implementation complete
- [x] Test suite created
- [x] Documentation comprehensive
- [x] Port configuration corrected (5964 for Ollama, 5965 for wrapper)
- [x] Systemd service file ready
- [x] Rollback plan documented
- [ ] Files copied to GPU server
- [ ] Wrapper tested manually
- [ ] Test suite passes (4/4)
- [ ] Service deployed and running
- [ ] THF configuration updated
- [ ] End-to-end test successful

---

**Status:** ✅ Ready for deployment. All development work complete. Ball is now in your court to deploy to GPU server.

**Estimated Deployment Time:** 10-15 minutes (following QUICK_START.md)

**Critical Success Factor:** Test 4 (tool calling) must PASS before considering deployment successful.

Good luck! 🚀
