"""
DeepSeek-R1 Wrapper for Wazuh Security Analysis (Docker Version)
Runs INSIDE Docker container on GPU server

Configuration for Docker setup:
- Listens on: 0.0.0.0:5964 (uses existing port mapping)
- Connects to Ollama on: localhost:11434 (Ollama default port inside container)
"""

from flask import Flask, request, jsonify, Response
import requests
import json
import re
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Ollama endpoint (inside Docker container)
# Try default Ollama port first
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "deepseek-r1:32b"

# Wazuh Security Analyst System Prompt
WAZUH_SYSTEM_PROMPT = """You are a Wazuh SIEM security analyst assistant using the ReAct (Reasoning and Acting) framework.

CRITICAL: You MUST respond in this EXACT format:

Thought: [your reasoning about what to do]
Action:
```
{
  "action": "tool_name",
  "action_input": {parameters}
}
```

FORMATTING RULES:
1. Start with "Thought:" followed by brief reasoning
2. Next line: "Action:"
3. Next line: Three backticks
4. Next lines: JSON object with "action" (tool name) and "action_input" (parameters)
5. Last line: Three backticks

DO NOT use any other format. This is the ONLY acceptable format.

EXAMPLE 1 - Count alerts by field:
Thought: The user wants to count alerts grouped by rule groups over the last 24 hours. I'll use analyze_alerts with action="counting" and group_by.
Action:
```
{
  "action": "analyze_alerts",
  "action_input": {
    "action": "counting",
    "group_by": "rule.groups",
    "time_range": "24h"
  }
}
```

EXAMPLE 2 - Count alerts by host:
Thought: The user wants to count alerts by host. I'll use action="counting" with group_by="host.name".
Action:
```
{
  "action": "analyze_alerts",
  "action_input": {
    "action": "counting",
    "group_by": "host.name",
    "time_range": "4h"
  }
}
```

EXAMPLE 3 - Filter critical alerts:
Thought: The user wants to see only critical alerts. I'll use action="filtering" with level filter.
Action:
```
{
  "action": "analyze_alerts",
  "action_input": {
    "action": "filtering",
    "filters": {
      "rule.level": {"gte": 12}
    },
    "time_range": "24h"
  }
}
```

EXAMPLE 4 - Rank top alerts:
Thought: The user wants to see the most frequent alerts. I'll use action="ranking".
Action:
```
{
  "action": "analyze_alerts",
  "action_input": {
    "action": "ranking",
    "group_by": "rule.description",
    "limit": 10,
    "time_range": "7d"
  }
}
```

AVAILABLE TOOLS:
You have access to specialized Wazuh security analysis tools that query real OpenSearch data:

1. analyze_alerts - Use this to:
   - Count alerts
   - Filter alerts by various criteria
   - Rank alerts by frequency
   - Get alert distribution statistics

2. investigate_entity - Use this to:
   - Investigate specific hosts, users, processes, files, or IPs
   - Get detailed information about entities
   - Retrieve alerts for specific entities

3. detect_threats - Use this to:
   - Find MITRE ATT&CK techniques
   - Identify threat actors
   - Search for indicators of compromise (IoCs)

4. map_relationships - Use this to:
   - Map relationships between entities
   - Correlate activities across hosts/users

5. find_anomalies - Use this to:
   - Detect threshold anomalies
   - Find behavioral anomalies
   - Identify trend deviations

6. trace_timeline - Use this to:
   - Reconstruct event timelines
   - Track attack progression

7. check_vulnerabilities - Use this to:
   - Check for specific CVEs
   - Assess vulnerability status

8. monitor_agents - Use this to:
   - Check agent status
   - Monitor agent health

EXAMPLES OF CORRECT TOOL USAGE:

User: "Count alerts by rule group for the last 24 hours"
Your Response:
Action: analyze_alerts
Action Input: {"action": "count_by_field", "field": "rule.groups", "time_range": "24h"}

User: "Show me critical alerts from yesterday"
Your Response:
Action: analyze_alerts
Action Input: {"action": "filter_alerts", "filters": {"rule.level": {"gte": 12}}, "time_range": "24h"}

User: "Investigate host win10-01"
Your Response:
Action: investigate_entity
Action Input: {"entity_type": "host", "entity_value": "win10-01", "action": "get_details"}

NEVER respond with generic advice like "Use Splunk" or "Run this SQL query".
Always use the actual Wazuh tools to get real data.

When you receive tool results (starting with "Observation:"), analyze them and provide security insights to the user.
"""

def parse_deepseek_response(raw_response: str) -> dict:
    """
    Parse DeepSeek-R1 response to extract thinking and final answer

    Args:
        raw_response: Raw response from DeepSeek-R1 with <think> tags

    Returns:
        Dictionary with 'thinking' and 'answer' components
    """
    # Extract thinking content
    think_pattern = r'<think>(.*?)</think>'
    think_matches = re.findall(think_pattern, raw_response, re.DOTALL)
    thinking = '\n'.join(think_matches).strip() if think_matches else ''

    # Extract answer (everything outside <think> tags)
    answer = re.sub(think_pattern, '', raw_response, flags=re.DOTALL).strip()

    return {
        'thinking': thinking,
        'answer': answer,
        'raw': raw_response
    }

def format_for_react_agent(parsed_response: dict) -> str:
    """
    Format DeepSeek response for LangChain ReAct agent consumption

    Args:
        parsed_response: Parsed response with thinking and answer

    Returns:
        Formatted string that LangChain can parse
    """
    # Return just the answer, which should contain Action/Action Input format
    # if DeepSeek properly understood the tool calling instructions
    return parsed_response['answer']

@app.route('/api/chat', methods=['POST'])
def chat():
    """
    OpenAI-compatible chat endpoint that wraps Ollama DeepSeek-R1
    """
    try:
        # Get request data
        data = request.get_json()

        # Extract messages from request
        messages = data.get('messages', [])

        if not messages:
            return jsonify({'error': 'No messages provided'}), 400

        # Inject system prompt if not present or override existing
        system_message = {
            'role': 'system',
            'content': WAZUH_SYSTEM_PROMPT
        }

        # Remove any existing system messages and prepend ours
        user_messages = [msg for msg in messages if msg.get('role') != 'system']
        full_messages = [system_message] + user_messages

        # Log request
        logger.info(f"Received request with {len(user_messages)} user messages")
        if user_messages:
            logger.info(f"Latest message: {user_messages[-1].get('content', '')[:100]}")

        # Prepare Ollama request
        ollama_payload = {
            'model': MODEL_NAME,
            'messages': full_messages,
            'stream': False,
            'options': {
                'temperature': 0.1,
                'num_predict': 3000,
            }
        }

        # Call Ollama
        logger.info("Calling Ollama DeepSeek-R1...")
        start_time = datetime.now()

        ollama_response = requests.post(
            OLLAMA_URL,
            json=ollama_payload,
            timeout=120
        )

        elapsed = (datetime.now() - start_time).total_seconds()
        logger.info(f"Ollama responded in {elapsed:.2f}s")

        if ollama_response.status_code != 200:
            logger.error(f"Ollama error: {ollama_response.text}")
            return jsonify({
                'error': 'Ollama request failed',
                'details': ollama_response.text
            }), ollama_response.status_code

        # Parse Ollama response
        ollama_data = ollama_response.json()
        raw_content = ollama_data.get('message', {}).get('content', '')

        # Parse DeepSeek response (handle <think> tags)
        parsed = parse_deepseek_response(raw_content)

        logger.info(f"Response - Thinking: {len(parsed['thinking'])} chars, Answer: {len(parsed['answer'])} chars")
        logger.info(f"Answer preview: {parsed['answer'][:200]}")

        # Format for ReAct agent
        formatted_answer = format_for_react_agent(parsed)

        # Return OpenAI-compatible response
        response = {
            'id': f"chatcmpl-{datetime.now().timestamp()}",
            'object': 'chat.completion',
            'created': int(datetime.now().timestamp()),
            'model': MODEL_NAME,
            'choices': [{
                'index': 0,
                'message': {
                    'role': 'assistant',
                    'content': formatted_answer
                },
                'finish_reason': 'stop'
            }],
            'usage': {
                'prompt_tokens': ollama_data.get('prompt_eval_count', 0),
                'completion_tokens': ollama_data.get('eval_count', 0),
                'total_tokens': ollama_data.get('prompt_eval_count', 0) + ollama_data.get('eval_count', 0)
            }
        }

        return jsonify(response)

    except requests.Timeout:
        logger.error("Ollama request timed out")
        return jsonify({'error': 'Request timed out'}), 504

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat/completions', methods=['POST'])
def chat_completions():
    """
    OpenAI-compatible /v1/chat/completions endpoint
    This is what ChatOpenAI from langchain-openai expects
    """
    return chat()

@app.route('/api/generate', methods=['POST'])
def generate():
    """
    Ollama-compatible generate endpoint (for compatibility)
    Converts to chat format internally
    """
    try:
        data = request.get_json()
        prompt = data.get('prompt', '')

        # Convert to chat format
        messages = [
            {'role': 'system', 'content': WAZUH_SYSTEM_PROMPT},
            {'role': 'user', 'content': prompt}
        ]

        # Call chat endpoint logic
        return chat_with_messages(messages)

    except Exception as e:
        logger.error(f"Error in generate endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

def chat_with_messages(messages):
    """Helper function to process chat with specific messages"""
    # Create fake request context
    original_json = request.get_json
    request.get_json = lambda: {'messages': messages}
    result = chat()
    request.get_json = original_json
    return result

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    try:
        # Check if Ollama is accessible
        response = requests.get('http://localhost:11434/api/tags', timeout=5)
        ollama_healthy = response.status_code == 200

        return jsonify({
            'status': 'healthy' if ollama_healthy else 'degraded',
            'ollama_accessible': ollama_healthy,
            'ollama_url': OLLAMA_URL,
            'model': MODEL_NAME,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 503

@app.route('/api/tags', methods=['GET'])
def tags():
    """
    Ollama-compatible tags endpoint
    Returns available models
    """
    try:
        response = requests.get('http://localhost:11434/api/tags', timeout=5)
        return Response(response.content, status=response.status_code, mimetype='application/json')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/', methods=['GET'])
def root():
    """Root endpoint with info"""
    return jsonify({
        'service': 'DeepSeek-R1 Wazuh Wrapper (Docker)',
        'model': MODEL_NAME,
        'ollama_url': OLLAMA_URL,
        'description': 'OpenAI-compatible API wrapper for DeepSeek-R1 with Wazuh security analyst prompting',
        'endpoints': {
            '/api/chat': 'OpenAI-compatible chat endpoint',
            '/api/generate': 'Ollama-compatible generate endpoint',
            '/health': 'Health check',
            '/api/tags': 'List available models'
        },
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("Starting DeepSeek-R1 Wazuh Wrapper (Docker Version)")
    logger.info(f"Model: {MODEL_NAME}")
    logger.info(f"Ollama URL: {OLLAMA_URL}")
    logger.info("Listening on: 0.0.0.0:5964")
    logger.info("=" * 60)
    logger.info("NOTE: Running inside Docker container")
    logger.info("      Using existing port 5964 mapping")
    logger.info("      Connecting to Ollama on localhost:11434")
    logger.info("=" * 60)

    app.run(
        host='0.0.0.0',
        port=5964,
        debug=False,
        threaded=True
    )
