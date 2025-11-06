"""
Wazuh Security Agent using LangChain
"""
from langchain.agents import initialize_agent, AgentType
from langchain.memory import ConversationSummaryBufferMemory
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from langchain.callbacks import LangChainTracer
from langchain_anthropic import ChatAnthropic
from typing import Dict, Any, List, Optional
import structlog
import os
import asyncio
from collections import defaultdict

from functions._shared.opensearch_client import WazuhOpenSearchClient
from tools.wazuh_tools import get_all_tools
from .context_processor import ConversationContextProcessor
from .query_complexity import QueryComplexityAnalyzer

logger = structlog.get_logger()

class WazuhSecurityAgent:
    """
    LangChain-based security agent for Wazuh SIEM
    """
    
    def __init__(self, anthropic_api_key: str, opensearch_config: Dict[str, Any],
                 local_model_config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Wazuh security agent

        Args:
            anthropic_api_key: Anthropic API key
            opensearch_config: OpenSearch connection configuration
            local_model_config: Optional local model configuration for hybrid setup
        """
        self.anthropic_api_key = anthropic_api_key
        self.opensearch_config = opensearch_config
        
        # Initialize OpenSearch client
        self.opensearch_client = WazuhOpenSearchClient(**opensearch_config)

        # Initialize Claude LLM (primary)
        self.llm_claude = ChatAnthropic(
            model="claude-sonnet-4-20250514",
            temperature=0.1,
            anthropic_api_key=anthropic_api_key,
            max_tokens=3000,  # Reduced to help prevent API overload
            timeout=30  # Add timeout for overload handling
        )

        # Initialize local model configuration
        self.llm_local = None
        self.local_model_config = local_model_config
        self.hybrid_mode = False
        self.complexity_threshold = 0.6
        self.current_model = "claude"

        # Initialize local model if configured
        if local_model_config and local_model_config.get("enabled", False):
            try:
                # Use ChatOpenAI for OpenAI-compatible wrapper (not ChatOllama)
                # ChatOpenAI automatically appends /chat/completions to base_url
                # Our wrapper expects /api/chat, so we need base_url to be .../api
                wrapper_url = local_model_config.get("url", "http://localhost:11434")
                # Remove trailing slash if present
                wrapper_url = wrapper_url.rstrip('/')
                # Append /api so ChatOpenAI will call /api/chat/completions (but our wrapper handles /api/chat)

                self.llm_local = ChatOpenAI(
                    model=local_model_config.get("model_name", "deepseek-r1:32b"),
                    base_url=f"{wrapper_url}/api",  # ChatOpenAI will append /chat/completions
                    api_key="dummy-key",  # Wrapper doesn't need auth, but field is required
                    temperature=0.1,
                    timeout=local_model_config.get("timeout", 120)
                )
                self.hybrid_mode = local_model_config.get("hybrid_mode", False)
                self.complexity_threshold = local_model_config.get("threshold", 0.6)
                logger.info("Local model initialized",
                           model=local_model_config.get("model_name"),
                           url=local_model_config.get("url"),
                           hybrid_mode=self.hybrid_mode)
            except Exception as e:
                logger.error("Failed to initialize local model", error=str(e))
                logger.info("Falling back to Claude only")

        # Set active LLM (default to Claude)
        self.llm = self.llm_claude
        
        # Initialize tools
        self.tools = get_all_tools(self.opensearch_client, self)
        
        # Initialize session-based memory storage
        self.session_memories = defaultdict(lambda: self._create_session_memory())
        self.current_session_id = None

        # Initialize default memory for backwards compatibility
        self.memory = self._create_session_memory()

        # Initialize context processor
        self.context_processor = ConversationContextProcessor()

        # Initialize query complexity analyzer (for routing)
        self.complexity_analyzer = QueryComplexityAnalyzer()

        # Initialize callbacks
        callbacks = []
        # Only enable LangSmith tracing if properly configured
        try:
            if os.getenv("LANGCHAIN_TRACING_V2") == "true" and os.getenv("LANGCHAIN_API_KEY"):
                callbacks.append(LangChainTracer())
                logger.info("LangSmith tracing enabled")
        except Exception as e:
            logger.warning("Failed to initialize LangSmith tracing", error=str(e))
        
        # Initialize agent
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            max_iterations=3,  # Reduced to save API calls
            early_stopping_method="generate",  # Generate response instead of force stopping
            callbacks=callbacks,
            handle_parsing_errors=True
        )
        
        # Enhanced system prompt with context preservation instructions
        self.system_prompt = """
        You are a Wazuh SIEM security analyst assistant. You help users investigate security incidents,
        analyze alerts, and understand their security posture.

        Key guidelines:
        - Always use the appropriate tools for data retrieval
        - Provide actionable security insights
        - Highlight critical findings and potential threats
        - Explain technical concepts in clear terms
        - Suggest follow-up investigations when relevant
        - Maintain security context in all responses
        - Focus on the most important security information
        - If a tool returns placeholder data, acknowledge it's not yet implemented

        Available tools cover:
        - Entity investigation for specific hosts, users, processes, files, IPs (investigate_entity)
        - Alert analysis and statistics across multiple alerts (analyze_alerts)
        - Threat detection and MITRE ATT&CK mapping (detect_threats)
        - Relationship mapping between entities (map_relationships)
        - Anomaly detection (find_anomalies)
        - Timeline reconstruction (trace_timeline)
        - Vulnerability checking (check_vulnerabilities)
        - Agent monitoring (monitor_agents)

        Always provide context about what the data means from a security perspective.

        Technical note: When context hints from previous input query like "these alerts", "this host", "this command, these processes", etc appear, consider using previous input parameters to maintain query continuity.
        """
        
        logger.info("Wazuh Security Agent initialized",
                   tools_count=len(self.tools),
                   primary_model="claude-sonnet-4",
                   local_model_available=self.llm_local is not None,
                   hybrid_mode=self.hybrid_mode)

    def _create_session_memory(self):
        """Create a new memory instance for a session"""
        # Use ConversationSummaryBufferMemory for better context management
        return ConversationSummaryBufferMemory(
            llm=self.llm,
            max_token_limit=1500,  # Reduced to prevent API overload
            memory_key="chat_history",
            return_messages=True,
            output_key="output"
        )

    def _get_session_memory(self, session_id: str):
        """Get or create memory for a specific session"""
        if session_id not in self.session_memories:
            logger.info("Creating new session memory", session_id=session_id)
        return self.session_memories[session_id]

    def _update_agent_memory(self, session_id: str):
        """Update the agent's memory to use the session-specific memory"""
        if self.current_session_id != session_id:
            self.current_session_id = session_id
            session_memory = self._get_session_memory(session_id)

            # Re-initialize agent with session-specific memory
            callbacks = []
            try:
                if os.getenv("LANGCHAIN_TRACING_V2") == "true" and os.getenv("LANGCHAIN_API_KEY"):
                    callbacks.append(LangChainTracer())
            except Exception as e:
                logger.warning("Failed to initialize LangSmith tracing", error=str(e))

            self.agent = initialize_agent(
                tools=self.tools,
                llm=self.llm,
                agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
                memory=session_memory,
                verbose=True,
                max_iterations=5,
                early_stopping_method="force",
                callbacks=callbacks,
                handle_parsing_errors=True
            )

            logger.info("Agent memory updated for session", session_id=session_id)

    def _route_to_model(self, user_input: str, chat_history: List = None) -> str:
        """
        Determine which model to use based on query complexity

        Args:
            user_input: User's query
            chat_history: Conversation history for context

        Returns:
            Model name: "claude" or "deepseek"
        """
        # If hybrid mode is disabled, always use Claude
        if not self.hybrid_mode or self.llm_local is None:
            return "claude"

        # Check for forced model override from environment
        force_model = os.getenv("FORCE_MODEL", "none").lower()
        if force_model in ["claude", "deepseek"]:
            logger.info("Using forced model from environment", model=force_model)
            return force_model

        # Compute query complexity
        complexity_result = self.complexity_analyzer.compute_complexity(
            user_input,
            conversation_history=chat_history
        )

        # Determine if should use local model
        use_local = self.complexity_analyzer.should_use_local_model(
            complexity_result,
            threshold=self.complexity_threshold
        )

        selected_model = "deepseek" if use_local else "claude"

        logger.info("Model routing decision",
                   selected_model=selected_model,
                   complexity_score=complexity_result['score'],
                   complexity_class=complexity_result['classification'],
                   threshold=self.complexity_threshold)

        return selected_model

    def _switch_model(self, target_model: str, session_id: str):
        """
        Switch active LLM and reinitialize agent

        Args:
            target_model: "claude" or "deepseek"
            session_id: Current session ID for memory context
        """
        # Check if switch is needed
        if target_model == self.current_model:
            logger.debug("Model switch not needed", current_model=self.current_model)
            return

        # Switch LLM
        if target_model == "deepseek" and self.llm_local:
            self.llm = self.llm_local
            self.current_model = "deepseek"
            logger.info("Switched to local model", model="deepseek-r1:32b")
        else:
            self.llm = self.llm_claude
            self.current_model = "claude"
            logger.info("Switched to Claude model", model="claude-sonnet-4")

        # Reinitialize agent with new LLM
        session_memory = self._get_session_memory(session_id)
        callbacks = []
        try:
            if os.getenv("LANGCHAIN_TRACING_V2") == "true" and os.getenv("LANGCHAIN_API_KEY"):
                callbacks.append(LangChainTracer())
        except Exception as e:
            logger.warning("Failed to initialize LangSmith tracing", error=str(e))

        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
            memory=session_memory,
            verbose=True,
            max_iterations=5,
            early_stopping_method="force",
            callbacks=callbacks,
            handle_parsing_errors=True
        )

        logger.info("Agent reinitialized with new model",
                   model=self.current_model,
                   session_id=session_id)

    async def query(self, user_input: str, session_id: str = "default") -> str:
        """
        Process user query and return response with session-based context

        Args:
            user_input: User's natural language query
            session_id: Unique session identifier for conversation context

        Returns:
            Agent's response
        """
        try:
            # Update agent memory for this session
            self._update_agent_memory(session_id)

            # Get conversation history for context analysis
            session_memory = self._get_session_memory(session_id)
            chat_history = session_memory.chat_memory.messages if hasattr(session_memory, 'chat_memory') else []

            # Process context separately from LLM prompt
            context_result = self.context_processor.process_query_with_context(user_input, chat_history)

            logger.info("Processing agent query with session context",
                       query_preview=user_input[:100],
                       session_id=session_id,
                       history_length=len(chat_history),
                       context_applied=context_result["context_applied"],
                       reasoning=context_result["reasoning"])

            # NEW: Route to appropriate model based on query complexity
            selected_model = self._route_to_model(user_input, chat_history)
            self._switch_model(selected_model, session_id)

            # Create enriched input with context for LLM when context is applied
            enriched_input = user_input
            if context_result["context_applied"]:
                enriched_input = self._create_context_enriched_input(user_input, context_result)

            # Execute agent with context-aware input (using routed model)
            response = await self._execute_with_retry(enriched_input, context_result, selected_model)

            logger.info("Agent query completed with context",
                       query_preview=user_input[:100],
                       session_id=session_id,
                       model_used=selected_model,
                       response_length=len(response))

            return response

        except Exception as e:
            logger.error("Agent query failed",
                        error=str(e),
                        query_preview=user_input[:100],
                        session_id=session_id)
            return f"I encountered an error processing your request: {str(e)}"

    async def _execute_with_retry(self, user_input: str, context_result: Dict[str, Any],
                                   selected_model: str, max_retries: int = 2) -> str:
        """
        Execute agent with retry logic for API overload and model fallback

        Args:
            user_input: User's query
            context_result: Context processing result
            selected_model: Initially selected model ("claude" or "deepseek")
            max_retries: Maximum retry attempts

        Returns:
            Agent's response
        """
        # Store context result for tool execution
        self._current_context_result = context_result
        current_model = selected_model
        attempted_fallback = False

        for attempt in range(max_retries + 1):
            try:
                # Agent expects input as dict with "input" key for STRUCTURED_CHAT type
                response = await self.agent.ainvoke({"input": user_input})
                # Extract the output from the response dict
                result = response.get("output", str(response))

                logger.info("Agent execution successful",
                           model_used=current_model,
                           fallback_used=attempted_fallback)

                return result

            except Exception as e:
                error_str = str(e)
                error_type = type(e).__name__

                # Log detailed error information for debugging
                logger.error("Agent execution error",
                           error_type=error_type,
                           error_message=error_str,
                           model=current_model,
                           user_input_preview=user_input[:200],
                           context_filters=context_result.get("suggested_filters", {}),
                           attempt=attempt + 1)

                # NEW: Fallback to Claude if DeepSeek fails with parsing/validation errors
                if current_model == "deepseek" and not attempted_fallback:
                    if any(keyword in error_str.lower() for keyword in
                           ["parsing", "validation", "json", "pydantic", "schema"]):
                        logger.warning("DeepSeek model failed, falling back to Claude",
                                     error_type=error_type,
                                     error_preview=error_str[:100])
                        # Switch to Claude and retry
                        self._switch_model("claude", self.current_session_id)
                        current_model = "claude"
                        attempted_fallback = True
                        continue

                if "overloaded" in error_str.lower() or "529" in error_str:
                    if attempt < max_retries:
                        wait_time = (2 ** attempt) * 2  # Exponential backoff: 2s, 4s
                        logger.warning(f"API overloaded, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries + 1})")
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        return "I apologize, but the system is currently experiencing high load. Please try your query again in a few moments, or try a more specific question to reduce processing requirements."
                elif "500" in error_str or "api_error" in error_str.lower():
                    # API 500 errors - provide helpful context
                    return f"The AI service encountered an error processing your query. This may be due to: (1) ambiguous entity references - try being more specific (e.g., use full process path instead of just name), (2) complex contextual queries - try rephrasing with explicit parameters, or (3) temporary API issues. Original error: {error_str}"
                else:
                    # Non-overload error, don't retry
                    raise e

        return "Unable to process request due to system overload."

    def _create_context_enriched_input(self, user_input: str, context_result: Dict[str, Any]) -> str:
        """
        Create enriched input that includes context information for the LLM

        Args:
            user_input: Original user input
            context_result: Result from context processor

        Returns:
            Enriched input with context guidance
        """
        suggested_filters = context_result.get("suggested_filters", {})
        suggested_time_range = context_result.get("suggested_time_range")

        # Build context hints
        context_parts = []

        if "host" in suggested_filters:
            context_parts.append(f'host {suggested_filters["host"]} (use "host": "{suggested_filters["host"]}")')

        if suggested_time_range:
            context_parts.append(f"timeframe {suggested_time_range}")

        if "rule.level" in suggested_filters:
            level_filter = suggested_filters["rule.level"]
            if isinstance(level_filter, dict) and "gte" in level_filter:
                if level_filter["gte"] == 12:
                    context_parts.append('critical alerts (use "rule.level": {"gte": 12})')
                elif level_filter["gte"] == 8:
                    context_parts.append('high severity alerts (use "rule.level": {"gte": 8})')

        if "rule.groups" in suggested_filters:
            groups = suggested_filters["rule.groups"]
            if isinstance(groups, list):
                context_parts.append(f"rule groups {', '.join(groups)}")

        # Create enriched input
        if context_parts:
            context_hint = f"[Context from previous query: {', '.join(context_parts)}] "
            enriched_input = context_hint + user_input

            logger.info("Created context-enriched input",
                       original=user_input,
                       context_parts=context_parts,
                       enriched_preview=enriched_input[:150])

            return enriched_input

        return user_input

    async def reset_memory(self, session_id: str = None):
        """Reset conversation memory for a session or all sessions"""
        try:
            if session_id:
                # Reset specific session
                if session_id in self.session_memories:
                    self.session_memories[session_id].clear()
                    logger.info("Session memory reset", session_id=session_id)
                else:
                    logger.info("Session not found for reset", session_id=session_id)
            else:
                # Reset all sessions
                self.session_memories.clear()
                self.current_session_id = None
                self.memory.clear()
                logger.info("All session memories reset")
        except Exception as e:
            logger.error("Failed to reset memory", error=str(e), session_id=session_id)
            raise

    def get_session_info(self, session_id: str = None) -> dict:
        """Get information about active sessions"""
        if session_id:
            session_memory = self.session_memories.get(session_id)
            if session_memory and hasattr(session_memory, 'chat_memory'):
                return {
                    "session_id": session_id,
                    "message_count": len(session_memory.chat_memory.messages),
                    "exists": True
                }
            return {"session_id": session_id, "exists": False}
        else:
            return {
                "total_sessions": len(self.session_memories),
                "active_sessions": list(self.session_memories.keys()),
                "current_session": self.current_session_id
            }

    async def test_connection(self) -> bool:
        """
        Test connection to OpenSearch
        
        Returns:
            True if connection successful
        """
        try:
            return await self.opensearch_client.test_connection()
        except Exception as e:
            logger.error("Connection test failed", error=str(e))
            return False
    
    async def get_available_indices(self) -> List[str]:
        """
        Get list of available Wazuh indices
        
        Returns:
            List of index names
        """
        try:
            return await self.opensearch_client.get_indices()
        except Exception as e:
            logger.error("Failed to get indices", error=str(e))
            return []
    
    async def close(self):
        """Close connections and cleanup"""
        try:
            await self.opensearch_client.close()
            logger.info("Agent connections closed")
        except Exception as e:
            logger.error("Error closing agent connections", error=str(e))
    
    def get_tool_descriptions(self) -> Dict[str, str]:
        """
        Get descriptions of available tools
        
        Returns:
            Dictionary mapping tool names to descriptions
        """
        return {tool.name: tool.description for tool in self.tools}
    
    def get_system_info(self) -> Dict[str, Any]:
        """
        Get system information
        
        Returns:
            Dictionary with system information
        """
        return {
            "model": "claude-4-sonnet",
            "tools_available": len(self.tools),
            "tool_names": [tool.name for tool in self.tools],
            "opensearch_host": self.opensearch_config.get("host"),
            "opensearch_port": self.opensearch_config.get("port"),
            "memory_type": "ConversationSummaryBufferMemory (Session-based)",
            "active_sessions": len(self.session_memories),
            "agent_type": "Structured Chat Zero Shot React Description"
        }