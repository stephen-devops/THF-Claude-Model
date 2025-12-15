"""
Mistral Large 2 Wrapper for Wazuh Security Analysis (Docker Version)
Runs INSIDE Docker container on GPU server

Configuration for Docker setup:
- Listens on: 0.0.0.0:5964 (uses existing port mapping)
- Connects to Ollama on: localhost:11434 (Ollama default port inside container)
"""

from flask import Flask, request, jsonify, Response
import requests
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
MODEL_NAME = "mistral-large:123b-instruct-2407-q2_K"

# Threat Hunting Analysis System Prompt (Claude-inspired approach)
THREAT_HUNTING_REPORT_PROMPT = """You are a Wazuh SIEM security analyst assistant. You help analysts investigate security incidents, analyze alerts, and understand their security posture.

Your role is to provide focused security analysis that adds context to the data without being overly prescriptive.

Key guidelines:
- Provide actionable security insights
- Highlight critical findings and potential threats
- Explain technical concepts in clear terms
- Suggest follow-up investigations when relevant
- Focus on the most important security information
- Trust the analyst to develop their own detailed response plans

Response approach:
- Keep responses concise and focused
- Identify the key security concern or pattern in the data
- Explain what the data indicates from a security perspective
- Provide 2-3 specific follow-up suggestions
- Add threat context (MITRE ATT&CK, known TTPs) where relevant

FORMATTING GUIDELINES:
- Use **bold** for emphasising critical findings, severity levels, or entities (hosts, processes, users, files)
- Use bullet points for clear organization
- Use headers (##) sparingly, only when needed for longer responses
- Keep the narrative flowing naturally without visual breaks

OUTPUT EXPECTATION:
Provide clear, focused security analysis that helps analysts understand what the data means and what areas to investigate further.
Write in clear, professional prose that analysts can read and act on quickly.
"""

@app.route('/api/chat', methods=['POST'])
def chat():
    """
    OpenAI-compatible chat endpoint that wraps Ollama Mistral Large 2
    """
    try:
        # Get request data
        data = request.get_json()

        # Extract messages from request
        messages = data.get('messages', [])

        if not messages:
            return jsonify({'error': 'No messages provided'}), 400

        # Inject threat hunting report system prompt
        system_message = {
            'role': 'system',
            'content': THREAT_HUNTING_REPORT_PROMPT
        }

        # Remove any existing system messages and prepend ours
        user_messages = [msg for msg in messages if msg.get('role') != 'system']
        full_messages = [system_message] + user_messages

        # Log request
        logger.info(f"Received request with {len(user_messages)} user messages")
        if user_messages:
            logger.info(f"Latest message: {user_messages[-1].get('content', '')[:100]}")

        # Prepare Ollama request optimized for Mistral Large 2
        ollama_payload = {
            'model': MODEL_NAME,
            'messages': full_messages,
            'stream': False,
            'options': {
                'temperature': 0.1,       # Low temperature for consistent security analysis
                'num_predict': 1500,      # Target detailed but focused responses
                'top_p': 0.9,             # Standard nucleus sampling
                'top_k': 40,              # Standard vocabulary restriction
                'repeat_penalty': 1.1,    # Slight penalty to avoid repetition
                'num_ctx': 4096,          # Larger context for complex security queries
                'num_thread': 8,          # CPU threads for model operations
                'num_gpu': 1,             # Use single GPU (adjust if using multiple)
            }
        }

        # Call Ollama
        logger.info("Calling Ollama Mistral Large 2...")
        start_time = datetime.now()

        ollama_response = requests.post(
            OLLAMA_URL,
            json=ollama_payload,
            timeout=300  # Increased timeout for first inference
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

        logger.info(f"Response length: {len(raw_content)} chars")
        logger.info(f"Answer preview: {raw_content[:200]}")

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
                    'content': raw_content
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

        # Convert to chat format with threat hunting prompt
        messages = [
            {'role': 'system', 'content': THREAT_HUNTING_REPORT_PROMPT},
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
        'service': 'Mistral Large 2 Threat Hunting Report Generator (Docker)',
        'model': MODEL_NAME,
        'ollama_url': OLLAMA_URL,
        'purpose': 'Post-tool execution response generation for Wazuh SIEM',
        'description': 'Analyzes OpenSearch query results and generates comprehensive threat hunting reports',
        'usage': 'Used by wazuh_agent.py after tool execution for enhanced response generation',
        'endpoints': {
            '/api/chat': 'OpenAI-compatible chat endpoint',
            '/api/chat/completions': 'OpenAI-compatible completions endpoint',
            '/api/generate': 'Ollama-compatible generate endpoint',
            '/health': 'Health check',
            '/api/tags': 'List available models'
        },
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    logger.info("=" * 80)
    logger.info("Starting Mistral Large 2 Threat Hunting Report Generator (Docker Version)")
    logger.info(f"Model: {MODEL_NAME}")
    logger.info(f"Ollama URL: {OLLAMA_URL}")
    logger.info("Listening on: 0.0.0.0:5964")
    logger.info("=" * 80)
    logger.info("PURPOSE: Post-tool execution response generation")
    logger.info("         - Analyzes OpenSearch query results")
    logger.info("         - Generates threat hunting reports")
    logger.info("         - Provides security context and recommendations")
    logger.info("=" * 80)
    logger.info("NOTE: Running inside Docker container")
    logger.info("      Using existing port 5964 mapping")
    logger.info("      Connecting to Ollama on localhost:11434")
    logger.info("=" * 80)

    app.run(
        host='0.0.0.0',
        port=5964,
        debug=False,
        threaded=True
    )
