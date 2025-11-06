# DeepSeek-R1 Wazuh Wrapper Deployment Guide

## Overview

This wrapper runs on your GPU server (192.168.200.205) and provides an OpenAI-compatible API that wraps Ollama DeepSeek-R1 with Wazuh-specific security analyst prompting.

## Architecture

```
THF App (Local) → Wrapper (GPU:5965) → Ollama (GPU:5964) → DeepSeek-R1
                   Port 5965           Port 5964 (your existing setup)
```

**Port Configuration:**
- **Port 5964:** Ollama (your existing setup from earlier testing)
- **Port 5965:** Wrapper (new layer that adds system prompts)

## Deployment Steps

### 1. Copy Files to GPU Server

```bash
# On your local machine
scp gpu_server_wrapper/deepseek_wazuh_wrapper.py stephen@192.168.200.205:~/
scp gpu_server_wrapper/requirements.txt stephen@192.168.200.205:~/
scp gpu_server_wrapper/deepseek-wrapper.service stephen@192.168.200.205:~/
```

### 2. Install Dependencies on GPU Server

```bash
# SSH into GPU server
ssh stephen@192.168.200.205

# Create virtual environment (optional but recommended)
python3 -m venv ~/deepseek-wrapper-env
source ~/deepseek-wrapper-env/bin/activate

# Install dependencies
pip install flask requests
```

### 3. Test the Wrapper Manually

```bash
# Make sure Ollama is running
ollama list  # Should show deepseek-r1:32b

# Run wrapper in test mode
python3 ~/deepseek_wazuh_wrapper.py
```

**You should see:**
```
============================================================
Starting DeepSeek-R1 Wazuh Wrapper
Model: deepseek-r1:32b
Ollama URL: http://localhost:5964/api/chat
Listening on: 0.0.0.0:5965
============================================================
```

### 4. Test from Local Machine

```bash
# From your Windows machine
curl http://192.168.200.205:5965/health

# Should return:
# {"status":"healthy","ollama_accessible":true,"model":"deepseek-r1:32b","timestamp":"..."}
```

### 5. Set Up as Systemd Service (Production)

```bash
# Copy service file
sudo cp ~/deepseek-wrapper.service /etc/systemd/system/

# Edit service file to set correct paths
sudo nano /etc/systemd/system/deepseek-wrapper.service

# Update these lines:
# User=stephen  (your username)
# WorkingDirectory=/home/stephen
# ExecStart=/home/stephen/deepseek-wrapper-env/bin/python3 /home/stephen/deepseek_wazuh_wrapper.py

# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable deepseek-wrapper

# Start service
sudo systemctl start deepseek-wrapper

# Check status
sudo systemctl status deepseek-wrapper
```

### 6. View Logs

```bash
# Follow logs in real-time
sudo journalctl -u deepseek-wrapper -f

# View recent logs
sudo journalctl -u deepseek-wrapper -n 100
```

### 7. Update THF Configuration (Local Machine)

Update your `.env` file to point to the wrapper:

```env
LOCAL_MODEL_URL=http://192.168.200.205:5965
```

**The wrapper provides the same API interface that your THF app expects, but with enhanced prompting!**

## How It Works

### System Prompt Injection

The wrapper automatically injects this system prompt into every request:

```
You are a Wazuh SIEM security analyst assistant...

CRITICAL INSTRUCTIONS FOR TOOL CALLING:
- You MUST use the provided tools to retrieve data
- NEVER make up data or provide generic SQL/Splunk examples
...
```

### Response Processing

1. **Receives request** from THF app with user query
2. **Injects Wazuh system prompt** before sending to DeepSeek
3. **Calls Ollama** with properly formatted request
4. **Parses DeepSeek response** (handles `<think>` tags)
5. **Extracts answer** (strips reasoning traces if needed)
6. **Returns OpenAI-compatible JSON** to THF app

### Example Flow

**User Query:** "Count alerts by rule group for the last 24 hours"

**Wrapper adds system prompt → DeepSeek receives:**
```
System: You are a Wazuh SIEM security analyst... [full prompt]
User: Count alerts by rule group for the last 24 hours
```

**DeepSeek responds:**
```
<think>
The user wants to count alerts by rule groups. I should use the analyze_alerts tool...
</think>

Action: analyze_alerts
Action Input: {"action": "count_by_field", "field": "rule.groups", "time_range": "24h"}
```

**Wrapper strips `<think>` tags → Returns to THF:**
```
Action: analyze_alerts
Action Input: {"action": "count_by_field", "field": "rule.groups", "time_range": "24h"}
```

**LangChain agent can now parse this correctly!**

## Monitoring

### Check if wrapper is running:

```bash
curl http://192.168.200.205:5965/health
```

### Check GPU server logs:

```bash
sudo journalctl -u deepseek-wrapper -f
```

### Check from THF app logs:

Look for lines like:
```
Model routing decision: selected_model=deepseek
Switched to local model: model=deepseek-r1:32b
```

## Troubleshooting

### Wrapper not accessible from local machine

```bash
# Check firewall on GPU server
sudo ufw status
sudo ufw allow 5965/tcp  # Allow wrapper port

# Or temporarily disable firewall for testing
sudo ufw disable
```

### Wrapper can't connect to Ollama

```bash
# Check Ollama is running
ollama list

# Check Ollama API (on your setup it's port 5964, not default 11434)
curl http://localhost:5964/api/tags
```

### DeepSeek still not calling tools

**Check wrapper logs to see actual prompts:**
```bash
sudo journalctl -u deepseek-wrapper -n 50
```

Look for "Latest message" and "Answer preview" to see what DeepSeek is receiving/returning.

**If still giving generic advice, we may need to:**
1. Strengthen the system prompt even more
2. Add few-shot examples in the prompt
3. Adjust DeepSeek model parameters

## Stopping/Restarting Service

```bash
# Stop
sudo systemctl stop deepseek-wrapper

# Start
sudo systemctl start deepseek-wrapper

# Restart
sudo systemctl restart deepseek-wrapper

# Disable (prevent auto-start on boot)
sudo systemctl disable deepseek-wrapper
```

## Performance Tuning

### Adjust timeout in wrapper:

Edit `deepseek_wazuh_wrapper.py`:
```python
timeout=120  # Increase if queries timeout
```

### Adjust Ollama parameters:

Edit in wrapper:
```python
'options': {
    'temperature': 0.1,      # Lower = more deterministic
    'num_predict': 3000,     # Max tokens
    'num_ctx': 8192,         # Context window
}
```

## Security Considerations

### Current setup (development):
- ✅ Runs on internal network (192.168.x.x)
- ❌ No authentication
- ❌ No HTTPS

### For production:
- Add API key authentication
- Use HTTPS with reverse proxy (nginx)
- Restrict access by IP
- Rate limiting

## Next Steps After Deployment

1. **Deploy wrapper to GPU server**
2. **Test health endpoint**
3. **Restart THF app** with `FORCE_MODEL=none` (to enable routing)
4. **Try test query:** "Count alerts by rule group for the last 24 hours"
5. **Check logs on both machines** to verify tool calling works
6. **If successful:** Gradually increase DeepSeek traffic percentage
7. **If still failing:** Check troubleshooting section above

## Fallback Plan

If wrapper doesn't solve the problem, you can easily revert:

```bash
# On GPU server, stop wrapper
sudo systemctl stop deepseek-wrapper

# On local machine, force Claude
# Edit .env: FORCE_MODEL=claude

# Restart THF app
```

Everything will work exactly as before.
