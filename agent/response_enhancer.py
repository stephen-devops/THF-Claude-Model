"""
Threat Hunting Response Enhancer

Uses DeepSeek-R1 for post-tool execution response generation.
Takes raw OpenSearch results and generates comprehensive threat hunting reports.

Architecture Flow:
    Claude (Tool Selection) → Tools Execute → Raw Results →
    DeepSeek-R1 (Response Enhancement) → Enhanced Threat Report → User
"""

import structlog
from typing import Dict, Any, Optional
from langchain_openai import ChatOpenAI

logger = structlog.get_logger(__name__)


class ThreatHuntingResponseEnhancer:
    """
    Uses DeepSeek-R1 to generate comprehensive threat hunting reports
    from raw tool execution results.

    NOT used for tool calling - only for response analysis and generation.
    """

    def __init__(self, deepseek_config: Optional[Dict[str, Any]] = None):
        """
        Initialize the response enhancer with DeepSeek-R1

        Args:
            deepseek_config: Configuration for DeepSeek-R1 endpoint
                {
                    "enabled": bool,
                    "url": str (e.g., "http://192.168.200.205:5964"),
                    "timeout": int (default: 120)
                }
        """
        self.enabled = False
        self.llm = None

        if deepseek_config and deepseek_config.get("enabled", False):
            try:
                wrapper_url = deepseek_config.get("url", "http://192.168.200.205:5964")
                wrapper_url = wrapper_url.rstrip('/')

                # Initialize ChatOpenAI to connect to DeepSeek wrapper
                self.llm = ChatOpenAI(
                    model="deepseek-r1:32b",  # Model name (informational)
                    base_url=f"{wrapper_url}/api",  # Wrapper endpoint
                    api_key="dummy-key",  # Not needed but required by ChatOpenAI
                    temperature=0.3,  # Slightly higher for more creative analysis
                    timeout=deepseek_config.get("timeout", 120),
                    max_tokens=4000  # Longer responses for comprehensive reports
                )

                self.enabled = True
                logger.info("Threat Hunting Response Enhancer initialized",
                           url=wrapper_url,
                           model="deepseek-r1:32b")

            except Exception as e:
                logger.error("Failed to initialize Response Enhancer", error=str(e))
                logger.info("Response enhancement disabled - using default responses")
                self.enabled = False
        else:
            logger.info("Response enhancement disabled by configuration")

    async def enhance_response(
        self,
        user_query: str,
        raw_tool_results: str,
        tool_name: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate enhanced threat hunting report from raw tool results

        Args:
            user_query: Original user query
            raw_tool_results: Raw results from tool execution (JSON/text)
            tool_name: Name of the tool that was executed
            context: Additional context (session info, previous queries, etc.)

        Returns:
            Enhanced threat hunting report with analysis and recommendations
        """
        if not self.enabled or not self.llm:
            # If disabled, return raw results
            logger.debug("Response enhancement disabled, returning raw results")
            return raw_tool_results

        try:
            # Build the analysis prompt
            analysis_prompt = self._build_analysis_prompt(
                user_query,
                raw_tool_results,
                tool_name,
                context
            )

            logger.info("Generating enhanced threat hunting report",
                       tool=tool_name,
                       query_preview=user_query[:100],
                       result_size=len(raw_tool_results))

            # Call DeepSeek-R1 for analysis
            response = await self.llm.ainvoke(analysis_prompt)

            logger.info("DeepSeek LLM call completed")

            # Extract content from response
            enhanced_report = response.content if hasattr(response, 'content') else str(response)

            logger.info("Enhanced report generated",
                       tool=tool_name,
                       report_length=len(enhanced_report))

            return enhanced_report

        except Exception as e:
            logger.error("Failed to generate enhanced response",
                        error=str(e),
                        tool=tool_name)
            # Fallback to raw results on error
            return raw_tool_results

    def _build_analysis_prompt(
        self,
        user_query: str,
        raw_results: str,
        tool_name: str,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """
        Build the analysis prompt for DeepSeek-R1 (simplified approach)

        Args:
            user_query: Original user query
            raw_results: Raw tool results
            tool_name: Tool that was executed
            context: Additional context

        Returns:
            Formatted prompt for analysis
        """
        # Build context string if available
        context_str = ""
        if context:
            context_items = []
            if context.get("session_id"):
                context_items.append(f"Session: {context['session_id']}")
            if context.get("previous_queries"):
                context_items.append(f"Previous queries in session: {context['previous_queries']}")
            if context_items:
                context_str = f"\n\nSession Context:\n" + "\n".join(context_items)

        # Pass raw OpenSearch data to DeepSeek for response generation
        prompt = f"""Analyze the following raw OpenSearch query results and generate a security analysis report.

User Query: {user_query}
Tool Executed: {tool_name}

Raw OpenSearch Data:
```
{raw_results}
```
{context_str}

Transform this raw data into a clear security analysis report following the key guidelines."""

        return prompt

    def is_enabled(self) -> bool:
        """Check if response enhancement is enabled"""
        return self.enabled

    async def test_connection(self) -> bool:
        """
        Test connection to DeepSeek-R1 endpoint

        Returns:
            True if connection successful, False otherwise
        """
        if not self.enabled or not self.llm:
            return False

        try:
            test_prompt = "Test connection. Respond with 'OK' if you receive this."
            response = await self.llm.ainvoke(test_prompt)
            logger.info("DeepSeek-R1 connection test successful")
            return True
        except Exception as e:
            logger.error("DeepSeek-R1 connection test failed", error=str(e))
            return False
