"""
Security Policy Enforcement Engine.
Enforces backend-side access control between untrusted input and AI agents/summarizers.
Browser verdicts and client-submitted flags are NEVER trusted.
"""

from typing import Tuple, Dict
from backend.schemas import RiskLevel, RecommendedAction
from backend.detection import engine


class PolicyEnforcementError(Exception):
    """Raised when an action violates security policy."""
    pass


def evaluate_policy(detection_result: Dict) -> Tuple[bool, RecommendedAction, str]:
    """
    Evaluates policy according to backend detection risk level.
    Returns (is_allowed, final_action, decision_message).
    """
    risk_level = detection_result.get("risk_level")
    risk_score = detection_result.get("risk_score", 0)

    if risk_level == RiskLevel.HIGH or risk_score >= 70:
        return (
            False,
            RecommendedAction.BLOCK,
            "Security Policy Enforcement: Content is blocked from AI agents due to HIGH risk prompt-injection directives.",
        )
    elif risk_level == RiskLevel.MEDIUM or risk_score >= 30:
        return (
            True,
            RecommendedAction.REVIEW,
            "Security Policy Enforcement: Content is permitted with caution. Proceeding in restricted sandbox mode.",
        )
    else:
        return (
            True,
            RecommendedAction.ALLOW,
            "Security Policy Enforcement: Content verified safe and permitted for AI summarization.",
        )


def enforce_summarization_gate(content: str, input_type: str = "email") -> Tuple[bool, Dict, str]:
    """
    Independent backend security gate before the AI summarizer.
    Always re-analyzes raw content using the detection engine on the backend.
    Any attempt by a malicious client to submit high-risk text directly to /summarize is caught and blocked here.
    """
    detection_result = engine.analyze(content, input_type=input_type)
    is_allowed, recommended_action, reason_msg = evaluate_policy(detection_result)

    return is_allowed, detection_result, reason_msg
