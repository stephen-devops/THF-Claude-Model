# DeepSeek Wrapper Deployment Checklist

## Pre-Deployment Verification

### ✅ Check Current Setup

- [ ] Verify Ollama is running on GPU server
  ```bash
  ssh stephen@192.168.200.205
  ollama list
  # Should show: deepseek-r1:32b
  ```

- [ ] Verify Ollama is on port 5964
  ```bash
  curl http://localhost:5964/api/tags
  # Should return JSON with models
  ```

- [ ] Verify THF app currently works with Claude
  ```bash
  # On local machine, .env should have:
  # FORCE_MODEL=claude
  ```

---

## Deployment Steps

### Step 1: Copy Files to GPU Server

```bash
# From local machine (Windows)
cd C:\Users\steph\PycharmProjects\THF-Claude-Model

# Copy all wrapper files
scp gpu_server_wrapper/deepseek_wazuh_wrapper.py stephen@192.168.200.205:~/
scp gpu_server_wrapper/requirements.txt stephen@192.168.200.205:~/
scp gpu_server_wrapper/deepseek-wrapper.service stephen@192.168.200.205:~/
```

**Status:** [ ] Completed

---

### Step 2: Install Dependencies on GPU Server

```bash
# SSH into GPU server
ssh stephen@192.168.200.205

# Install Python dependencies
pip3 install flask requests

# Or use virtual environment (recommended)
python3 -m venv ~/deepseek-env
source ~/deepseek-env/bin/activate
pip install flask requests
```

**Status:** [ ] Completed

---

### Step 3: Test Wrapper Manually (IMPORTANT!)

```bash
# On GPU server
python3 ~/deepseek_wazuh_wrapper.py

# You should see:
# ============================================================
# Starting DeepSeek-R1 Wazuh Wrapper
# Model: deepseek-r1:32b
# Ollama URL: http://localhost:5964/api/chat
# Listening on: 0.0.0.0:5965
# ============================================================
```

**Status:** [ ] Completed

**Don't proceed to Step 4 until this works!**

---

### Step 4: Test from Local Machine

**Open a new terminal on your local machine while wrapper is running:**

```bash
# Test health endpoint
curl http://192.168.200.205:5965/health

# Expected response:
# {"status":"healthy","ollama_accessible":true,"model":"deepseek-r1:32b",...}

# Run full test suite
cd C:\Users\steph\PycharmProjects\THF-Claude-Model
python gpu_server_wrapper/test_wrapper.py
```

**Expected test results:**
- [ ] Test 1: Health Check - PASS
- [ ] Test 2: Root Endpoint - PASS
- [ ] Test 3: Simple Chat - PASS
- [ ] Test 4: Tool Calling - **CRITICAL TEST** - PASS

**If Test 4 fails (tool calling), DO NOT proceed. Debug first!**

---

### Step 5: Check Firewall (If Health Check Failed)

```bash
# On GPU server
sudo ufw status

# If active, allow port 5965
sudo ufw allow 5965/tcp

# Reload firewall
sudo ufw reload

# Or temporarily disable for testing
sudo ufw disable
```

**Status:** [ ] Completed (if needed)

---

### Step 6: Set Up as Systemd Service (Production)

**Only after manual testing succeeds!**

```bash
# On GPU server

# If using virtual environment, update service file first
nano ~/deepseek-wrapper.service

# Change this line if using venv:
# ExecStart=/home/stephen/deepseek-env/bin/python3 /home/stephen/deepseek_wazuh_wrapper.py

# Copy to systemd
sudo cp ~/deepseek-wrapper.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable auto-start on boot
sudo systemctl enable deepseek-wrapper

# Start service
sudo systemctl start deepseek-wrapper

# Check status (should show "active (running)")
sudo systemctl status deepseek-wrapper
```

**Status:** [ ] Completed

---

### Step 7: Verify Service is Running

```bash
# On GPU server
sudo systemctl status deepseek-wrapper

# Should show:
# ● deepseek-wrapper.service - DeepSeek-R1 Wazuh Wrapper API
#    Loaded: loaded
#    Active: active (running)

# Check logs
sudo journalctl -u deepseek-wrapper -n 20
```

**Status:** [ ] Completed

---

### Step 8: Update Local THF Configuration

**On local machine, edit `.env`:**

```bash
# Change from:
FORCE_MODEL=claude

# To:
FORCE_MODEL=none

# Verify URL points to wrapper:
LOCAL_MODEL_URL=http://192.168.200.205:5965
```

**Status:** [ ] Completed

---

### Step 9: Restart THF Application

```bash
# On local machine
cd C:\Users\steph\PycharmProjects\THF-Claude-Model

# Stop current server (Ctrl+C)

# Restart
uvicorn main:app --host 0.0.0.0 --port 8000
```

**Check logs for:**
```
Local model initialized, model=deepseek-r1:32b, url=http://192.168.200.205:5965, hybrid_mode=True
```

**Status:** [ ] Completed

---

### Step 10: Critical Test - Tool Calling via UI

**Open Streamlit UI:** http://localhost:8501

**Enter query:** "Count alerts by rule group for the last 24 hours"

**Expected behavior:**
- Query should take 30-60 seconds
- Should see actual alert data (not generic SQL advice)
- Check local machine logs for: `Model routing decision: selected_model=deepseek`

**Result:** [ ] PASS / [ ] FAIL

---

## Success Criteria

### ✅ All these must be true:

- [ ] Wrapper service running on GPU server (port 5965)
- [ ] Health endpoint responds: `http://192.168.200.205:5965/health`
- [ ] Test suite passes all 4 tests
- [ ] THF app successfully routes queries to DeepSeek
- [ ] DeepSeek calls `analyze_alerts` tool (not generic advice)
- [ ] Actual Wazuh data is returned to user

---

## Monitoring After Deployment

### Watch Logs (Run in separate terminals)

**Terminal 1 - GPU Server Wrapper Logs:**
```bash
ssh stephen@192.168.200.205
sudo journalctl -u deepseek-wrapper -f
```

**Terminal 2 - Local THF Logs:**
```bash
cd C:\Users\steph\PycharmProjects\THF-Claude-Model
# FastAPI logs will show in uvicorn output
```

**Terminal 3 - Streamlit UI:**
```bash
streamlit run streamlit_ui.py
```

---

## Troubleshooting Checklist

### If Test 4 (Tool Calling) Fails:

- [ ] Check wrapper logs: `sudo journalctl -u deepseek-wrapper -n 50`
- [ ] Look for "Answer preview" in logs - does it contain "Action:"?
- [ ] Verify system prompt is being injected (check wrapper code)
- [ ] Try strengthening system prompt with more explicit examples
- [ ] Check if DeepSeek is generating `<think>` tags (normal)
- [ ] Verify wrapper is stripping `<think>` tags correctly

### If Connection Fails:

- [ ] Ping GPU server: `ping 192.168.200.205`
- [ ] Check port 5965: `curl http://192.168.200.205:5965/health`
- [ ] Check firewall: `sudo ufw status` on GPU server
- [ ] Verify Ollama is running: `curl http://localhost:5964/api/tags`
- [ ] Check wrapper is running: `sudo systemctl status deepseek-wrapper`

### If DeepSeek Still Gives Generic Advice:

**This means the system prompt isn't strong enough. You'll need to:**

1. Stop the wrapper service
2. Edit `deepseek_wazuh_wrapper.py` to strengthen the prompt
3. Add few-shot examples
4. Restart wrapper and test again

---

## Rollback Plan (If Everything Fails)

### Quick Rollback:

```bash
# On GPU server
sudo systemctl stop deepseek-wrapper

# On local machine, edit .env:
FORCE_MODEL=claude

# Restart THF app
# Ctrl+C, then: uvicorn main:app --host 0.0.0.0 --port 8000
```

**Everything will work exactly as before with Claude.**

---

## Performance Baseline

### First Query (After Deployment):

Record these metrics for comparison:

- Query: "Count alerts by rule group for the last 24 hours"
- Model used: [ ] Claude / [ ] DeepSeek
- Response time: _____ seconds
- Tool called: [ ] Yes (analyze_alerts) / [ ] No (generic advice)
- Data returned: [ ] Actual Wazuh data / [ ] Generic advice
- Quality: [ ] Good / [ ] Acceptable / [ ] Poor

---

## Next Steps After Success

If deployment succeeds:

1. [ ] Monitor for 1 day with 20% traffic to DeepSeek
2. [ ] Review logs for errors/failures
3. [ ] Compare response quality vs Claude
4. [ ] Calculate cost savings
5. [ ] Gradually increase DeepSeek traffic to 50%, then 70%

If deployment fails:

1. [ ] Review wrapper logs thoroughly
2. [ ] Check PORT_CONFIGURATION.md for setup issues
3. [ ] Consider strengthening system prompt
4. [ ] May need to try different local model (Llama3.1-70B)
5. [ ] Fallback to Claude-only approach

---

## Contact Information

**Deployment Date:** __________

**Deployed By:** __________

**GPU Server:** 192.168.200.205
**Local Machine:** 192.168.201.45

**Service Status Check:**
```bash
sudo systemctl status deepseek-wrapper
```

**Logs Location:**
```bash
sudo journalctl -u deepseek-wrapper
```

---

## Notes

(Space for deployment notes, issues encountered, solutions applied, etc.)

```


```
