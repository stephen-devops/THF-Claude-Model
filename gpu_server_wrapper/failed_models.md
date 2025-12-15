# Failed Local Model Attempts

This document tracks all local models attempted as replacements for Claude Sonnet 4.5 in the Wazuh SIEM security analysis application, including issues encountered and reasons for failure.

## Hardware Configuration
- **GPU Server**: 192.168.200.205 (Docker VM: resilmesh-cti-global)
- **GPUs**: 4x NVIDIA A100-SXM4-40GB (160GB total VRAM)
- **CUDA Version**: 12.3
- **Driver Version**: 545.23.06

## Application Requirements
- **Agent Type**: LangChain STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION (ReAct pattern)
- **Tool Count**: 8 security analysis tools with complex Pydantic schemas
- **Key Capabilities Needed**:
  - Function calling with structured JSON output
  - Multi-step reasoning (Thought → Action → Action Input → Observation)
  - OpenSearch query generation
  - Security context understanding
  - Tool parameter schema compliance (all required fields must be present)

---

## 1. Mistral Large 2 (123B) - Ollama

### Model Details
- **Size**: 123 billion parameters
- **Quantization**: q2_K (2-bit)
- **Expected Size**: ~30-40GB
- **Serving Method**: Ollama
- **Model Name**: `mistral-large:123b-instruct-2407-q2_K`

### Issues Encountered

#### Issue 1: GPU Allocation Failure
**Symptom**: Model ran on CPU (95%) instead of GPU (5%)

**Root Cause**: Ollama spawns child runner processes that don't inherit environment variables (`OLLAMA_NUM_GPU`, `OLLAMA_GPU_LAYERS`)

**Attempted Fixes**:
1. Created `/etc/ollama/ollama.conf` with GPU settings
2. Created systemd service override in `/etc/systemd/system/ollama.service.d/override.conf`
3. Created wrapper script `/usr/local/bin/ollama-gpu`
4. Set `OLLAMA_NUM_GPU=1` and `OLLAMA_GPU_LAYERS=89`

**Temporary Success**: Briefly achieved 73/89 layers on GPU (15% CPU / 85% GPU)

**Final Outcome**: GPU allocation lost after process restart. Configuration not persistent across model loads.

#### Issue 2: Request Timeouts
**Symptom**: 504 Gateway Timeout errors after 120 seconds

**Root Cause**: Running on CPU made inference too slow for real-time responses

**Error Logs**:
```
requests.exceptions.ReadTimeout: HTTPConnectionPool(host='192.168.200.205', port=5964):
Read timed out. (read timeout=120)
```

### Verdict
**FAILED** - Ollama cannot maintain persistent GPU allocation in Docker environment. Fundamental architecture limitation prevents reliable GPU usage.

---

## 2. Mistral Large 2 (123B) - vLLM

### Model Details
- **Size**: 123 billion parameters
- **Format**: HuggingFace (bfloat16)
- **Actual Size**: ~246 GB unquantized
- **Serving Method**: vLLM with tensor parallelism
- **Model Path**: `mistralai/Mistral-Large-Instruct-2407`

### Issues Encountered

#### Issue 1: CUDA Out of Memory
**Symptom**: Model failed to load across 4 GPUs

**Error**:
```
torch.OutOfMemoryError: CUDA out of memory.
Tried to allocate 336.00 MiB.
GPU 0: 37.81 GiB already allocated by PyTorch.
Only 1.56 MiB free in block.
```

**Analysis**:
- Model requires ~246 GB in bfloat16 precision
- With tensor-parallel-4: ~61.5 GB per GPU needed
- Available per GPU: 40 GB
- **Deficit**: 21.5 GB per GPU

**Attempted Fix**: Increased `gpu_memory_utilization` from 0.5 to 0.6 to 0.65 - insufficient

#### Issue 2: Disk Space Exhaustion
**Symptom**: Filled 10TB/11TB disk due to duplicate downloads

**Root Cause**: Model downloaded to both:
- `~/.cache/huggingface` (484 GB)
- `~/vLLMServers/Mistral-Large-Instruct-2407` (511 GB)

**Fix**: Removed cache directory to free 484 GB

### Verdict
**FAILED** - Model too large for available GPU memory. Would require 8x A100 40GB or 4x A100 80GB GPUs.

---

## 3. Mistral 7B Instruct v0.3

### Model Details
- **Size**: 7 billion parameters
- **Format**: HuggingFace safetensors
- **Actual Size**: ~14 GB
- **Context Length**: 8192 tokens
- **Serving Method**: vLLM (single GPU)
- **Model Path**: `mistralai/Mistral-7B-Instruct-v0.3`

### Issues Encountered

#### Issue 1: Insufficient Context Length
**Symptom**: Exceeded context window for tool-heavy queries

**Error**:
```
'max_tokens' is too large: 2000
Input tokens: 6642
Context length: 8192
Available for output: 1550 tokens (8192 - 6642)
```

**Analysis**:
- Tool definitions: ~6,642 tokens (81% of 8K context)
- System prompt: ~500 tokens
- User query: ~100 tokens
- **Remaining for response**: Only 1,550 tokens

**Fix Applied**: Reduced `max_tokens` from 3000 → 2000 → 1000 in `agent/wazuh_agent.py`

#### Issue 2: Poor Function Calling Quality
**Symptom**: Generated invalid OpenSearch queries and malformed JSON

**Examples of Failures**:
1. **Invalid field types**: Generated arrays for single-value fields
   ```json
   "query": {
     "match": {
       "agent.name": ["U209-PC-BLEE"]  // Should be string, not array
     }
   }
   ```

2. **Missing required fields**: Omitted mandatory parameters from tool schemas

3. **Incorrect query structure**: Malformed OpenSearch DSL syntax

**Analysis**: 7B parameter models lack the capacity for reliable structured output generation, especially with complex schemas.

### Verdict
**FAILED** - Too small for:
1. Adequate context length with 8 tools
2. Reliable function calling with complex Pydantic schemas
3. Valid OpenSearch query generation

---

## 4. Mistral Nemo 12B Instruct (CURRENT)

### Model Details
- **Size**: 12 billion parameters
- **Format**: HuggingFace safetensors
- **Actual Size**: ~22.84 GB
- **Context Length**: 8192 tokens (reduced from 16384 due to KV cache constraints)
- **Serving Method**: vLLM (single GPU)
- **Model Path**: `mistralai/Mistral-Nemo-Instruct-2407`

### Initial Loading Issues

#### Issue 1: Wrong Model Format Downloaded
**Symptom**: Downloaded NeMo format instead of HuggingFace format

**Error**: Downloaded from `nvidia/Mistral-NeMo-12B-Instruct` which contained `.nemo` file (NVIDIA NeMo Toolkit format)

**Fix**: Downloaded correct model from `mistralai/Mistral-Nemo-Instruct-2407`

#### Issue 2: Insufficient KV Cache for 16K Context
**Symptom**: Model loaded but insufficient memory for 16K context length

**Error**:
```
Model loading took 22.8447 GiB
Available KV cache memory: 1.50 GiB
Required for 16384 context: 2.50 GiB
Maximum possible context: 9840 tokens
```

**Fix**: Reduced `--max-model-len` from 16384 to 8192

**Current Resource Usage**:
- Model weights: 22.84 GiB
- KV cache: 1.50 GiB (9,840 tokens capacity)
- CUDA graphs: 3.46 GiB
- **Total**: ~26.3 GiB on single GPU

### Current Functional Issues

#### Issue 1: Missing Required Fields in Tool Calls
**Symptom**: Pydantic validation errors for incomplete tool arguments

**User Query**: "Show me an alert breakdown of host U209-PC-BLEE over the past 12 hours."

**Expected Tool Call**:
```python
{
  "action": "distribution",  # REQUIRED
  "group_by": "host",
  "filters": {"host": "U209-PC-BLEE"},
  "time_range": "12h"
}
```

**Actual Tool Call**:
```python
{
  "group_by": "host",
  "filters": {...},
  "time_range": "12h"
  # Missing required 'action' field
}
```

**Error**:
```
1 validation error for AnalyzeAlertsSchema
action
  Field required [type=missing, input_value={'group_by': 'host', 'fil...'}, 'time_range': '12h'}, input_type=dict]
```

**Analysis**: Model is attempting to call tools but not properly parsing Pydantic schemas to identify all required fields.

#### Issue 2: ReAct Format Compliance Unknown
**Status**: Not yet fully tested whether model can follow complete ReAct pattern:
- Thought: [reasoning]
- Action: [tool_name]
- Action Input: [complete JSON with all required fields]
- Observation: [tool result]

**Performance Metrics** (from vLLM):
- Prompt throughput: 455.5 tokens/s
- Generation throughput: 9.8 tokens/s
- Model loaded successfully, server responsive (200 OK responses)

### Verdict
**LIKELY INSUFFICIENT** - While model loads and serves successfully, it demonstrates poor function calling capability:
1. Missing required fields in tool arguments
2. Incomplete understanding of Pydantic schema requirements
3. May not reliably follow complex ReAct agent patterns

**Status**: Currently loaded and running, but not suitable for production use without further testing or falling back to hybrid mode.

---

## Summary Table

| Model | Size | Method | Context | GPU Usage | Status | Primary Issue |
|-------|------|--------|---------|-----------|--------|---------------|
| Mistral Large 2 123B | ~246GB | Ollama | 128K | 95% CPU/5% GPU | ❌ FAILED | GPU allocation not persistent |
| Mistral Large 2 123B | ~246GB | vLLM | 128K | OOM | ❌ FAILED | Too large for 4x A100 40GB |
| Mistral 7B v0.3 | ~14GB | vLLM | 8K | 1 GPU | ❌ FAILED | Context too small, poor function calling |
| Mistral Nemo 12B | ~23GB | vLLM | 8K | 1 GPU | ⚠️ LOADED | Missing required fields in tool calls |

---

## Recommendations

### Option A: Quantized 70B+ Models (Recommended)
Try larger models with aggressive quantization that fit in 160GB total VRAM:

1. **Llama 3.1 70B Instruct** (AWQ 4-bit): ~35GB
   - Better function calling than Mistral
   - Proven ReAct capability
   - 128K context length

2. **Qwen 2.5 72B Instruct** (GPTQ 4-bit): ~36GB
   - Excellent tool use
   - Strong reasoning
   - 32K context length

3. **DeepSeek-V2.5** (236B MoE, quantized): Requires evaluation
   - Large but sparse (MoE architecture)
   - Strong coding and reasoning
   - Need to verify actual memory footprint

### Option B: Hybrid Mode
- Use Claude Sonnet 4.5 for ReAct agent orchestration and tool selection
- Use local Mistral Nemo 12B only for final response generation after tool execution
- Already implemented in codebase (`HYBRID_MODE=true` in `.env`)
- Balances cost (fewer Claude API calls) with reliability (Claude handles complex reasoning)

### Option C: Simplify Tool Schemas
- Reduce from 8 tools to 2-3 essential tools
- Flatten Pydantic schemas to reduce complexity
- Remove nested optional fields
- **Downside**: Loses comprehensive security analysis capabilities

---

## Next Steps

1. **Immediate**: Test Option B (Hybrid Mode) to validate approach
2. **Short-term**: Acquire and test Llama 3.1 70B AWQ or Qwen 2.5 72B GPTQ
3. **Long-term**: Consider GPU upgrade (4x A100 80GB) or model distillation approach

---

## Technical Notes

### vLLM Configuration Used
```bash
python3 -m vllm.entrypoints.openai.api_server \
  --model ~/vLLMServers/Mistral-Nemo-Instruct-2407/snapshots/04d8a90549d23fc6bd7f642064003592df51e9b3/ \
  --host 0.0.0.0 \
  --port 5964 \
  --gpu-memory-utilization 0.65 \
  --dtype auto \
  --max-model-len 8192
```

### Memory Allocation Breakdown (A100 40GB)
- Total VRAM: 40,960 MiB
- Model weights: 22,845 MiB (55.8%)
- KV cache: 1,536 MiB (3.8%)
- CUDA graphs: 3,546 MiB (8.7%)
- PyTorch overhead: ~2,000 MiB (4.9%)
- **Available**: ~11,033 MiB (26.9%)

### Files Modified During Testing
- `.env`: Updated `LOCAL_MODEL_NAME` through multiple iterations
- `agent/wazuh_agent.py`: Reduced `max_tokens` from 3000 → 2000 → 1000
- Created `gpu_server_wrapper/mistral_wazuh_wrapper_docker.py` (now obsolete with direct vLLM)
- Created `gpu_server_wrapper/test_vllm.py` for capability testing

---

**Document Created**: 2025-12-12
**Last Updated**: 2025-12-12
**Status**: Active troubleshooting with Mistral Nemo 12B
