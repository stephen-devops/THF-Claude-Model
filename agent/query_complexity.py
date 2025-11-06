"""
Query Complexity Analyzer for Multi-Model Routing

Analyzes user queries to determine complexity score (0.0 - 1.0)
Used to route queries between DeepSeek (simple) and Claude (complex)
"""
import re
from typing import Dict, List
import structlog

logger = structlog.get_logger()


class QueryComplexityAnalyzer:
    """
    Analyzes query complexity to determine optimal model routing

    Scoring Factors:
    - Multi-step reasoning keywords
    - Number of entities referenced
    - Contextual references (these, those, etc.)
    - Multiple tool requirements
    - Temporal reasoning (anomalies, patterns)
    - MITRE ATT&CK / CVE references
    - Query length and ambiguity
    """

    def __init__(self):
        # Multi-step reasoning keywords
        self.multi_step_keywords = [
            'and then', 'after that', 'correlate', 'relate', 'combine',
            'investigate', 'analyze', 'compare', 'cross-reference',
            'followed by', 'in relation to'
        ]

        # Contextual reference keywords
        self.contextual_keywords = [
            'these', 'those', 'that', 'this', 'them', 'their',
            'related', 'associated', 'connected', 'similar',
            'above', 'previous', 'same'
        ]

        # Temporal/anomaly keywords
        self.temporal_keywords = [
            'unusual', 'anomal', 'strange', 'weird', 'abnormal',
            'pattern', 'trend', 'baseline', 'deviation',
            'spike', 'surge', 'drop', 'increase', 'decrease'
        ]

        # MITRE ATT&CK technique patterns
        self.mitre_pattern = re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE)

        # CVE pattern
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

        # Multiple entity indicators
        self.entity_indicators = [
            'host', 'user', 'process', 'file', 'ip', 'alert',
            'agent', 'rule', 'technique', 'tactic'
        ]

        # Complex operation keywords
        self.complex_operations = [
            'top', 'bottom', 'rank', 'count', 'sum', 'average',
            'group', 'aggregate', 'timeline', 'sequence'
        ]

    def compute_complexity(self, query: str, conversation_history: List = None) -> Dict:
        """
        Compute complexity score for a query

        Args:
            query: User's natural language query
            conversation_history: Optional conversation history for context

        Returns:
            Dictionary with score and reasoning breakdown
        """
        query_lower = query.lower()

        score = 0.0
        factors = {}

        # Factor 1: Multi-step reasoning (0.0 - 0.25)
        multi_step_count = sum(1 for kw in self.multi_step_keywords if kw in query_lower)
        multi_step_score = min(multi_step_count * 0.15, 0.25)
        score += multi_step_score
        factors['multi_step_reasoning'] = {
            'score': multi_step_score,
            'matches': multi_step_count
        }

        # Factor 2: Contextual references (0.0 - 0.20)
        contextual_count = sum(1 for kw in self.contextual_keywords if kw in query_lower)
        contextual_score = min(contextual_count * 0.10, 0.20)
        score += contextual_score
        factors['contextual_references'] = {
            'score': contextual_score,
            'matches': contextual_count
        }

        # Factor 3: Temporal/anomaly reasoning (0.0 - 0.15)
        temporal_count = sum(1 for kw in self.temporal_keywords if kw in query_lower)
        temporal_score = min(temporal_count * 0.08, 0.15)
        score += temporal_score
        factors['temporal_reasoning'] = {
            'score': temporal_score,
            'matches': temporal_count
        }

        # Factor 4: MITRE/CVE references (0.0 - 0.15)
        mitre_matches = len(self.mitre_pattern.findall(query))
        cve_matches = len(self.cve_pattern.findall(query))
        security_ref_score = min((mitre_matches + cve_matches) * 0.10, 0.15)
        score += security_ref_score
        factors['security_references'] = {
            'score': security_ref_score,
            'mitre_matches': mitre_matches,
            'cve_matches': cve_matches
        }

        # Factor 5: Multiple entities (0.0 - 0.10)
        entity_count = sum(1 for entity in self.entity_indicators if entity in query_lower)
        entity_score = min((entity_count - 1) * 0.05, 0.10) if entity_count > 1 else 0.0
        score += entity_score
        factors['multiple_entities'] = {
            'score': entity_score,
            'count': entity_count
        }

        # Factor 6: Complex operations (0.0 - 0.10)
        complex_op_count = sum(1 for op in self.complex_operations if op in query_lower)
        complex_op_score = min(complex_op_count * 0.05, 0.10)
        score += complex_op_score
        factors['complex_operations'] = {
            'score': complex_op_score,
            'matches': complex_op_count
        }

        # Factor 7: Query length (0.0 - 0.05)
        word_count = len(query.split())
        if word_count > 20:
            length_score = 0.05
        elif word_count > 15:
            length_score = 0.03
        else:
            length_score = 0.0
        score += length_score
        factors['query_length'] = {
            'score': length_score,
            'word_count': word_count
        }

        # Cap score at 1.0
        final_score = min(score, 1.0)

        result = {
            'score': final_score,
            'factors': factors,
            'classification': self._classify_complexity(final_score),
            'query_preview': query[:100]
        }

        logger.info("Query complexity analyzed",
                   score=final_score,
                   classification=result['classification'],
                   top_factors=self._get_top_factors(factors))

        return result

    def _classify_complexity(self, score: float) -> str:
        """Classify complexity score into categories"""
        if score < 0.4:
            return "simple"
        elif score < 0.6:
            return "medium"
        else:
            return "complex"

    def _get_top_factors(self, factors: Dict) -> List[str]:
        """Get top contributing factors for logging"""
        sorted_factors = sorted(
            [(k, v.get('score', 0)) for k, v in factors.items()],
            key=lambda x: x[1],
            reverse=True
        )
        return [k for k, s in sorted_factors[:3] if s > 0]

    def should_use_local_model(self, complexity_result: Dict, threshold: float = 0.6) -> bool:
        """
        Determine if query should use local model based on complexity

        Args:
            complexity_result: Result from compute_complexity()
            threshold: Complexity threshold (queries below use local model)

        Returns:
            True if should use local model (DeepSeek), False if should use Claude
        """
        score = complexity_result['score']
        use_local = score < threshold

        logger.debug("Model routing decision",
                    score=score,
                    threshold=threshold,
                    use_local=use_local,
                    model="deepseek" if use_local else "claude")

        return use_local
