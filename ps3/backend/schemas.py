from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class InputType(str, Enum):
    EMAIL = "email"
    WEBPAGE = "webpage"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RecommendedAction(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class PatternMatchDetail(BaseModel):
    category: str = Field(..., description="High-level attack category")
    pattern_name: str = Field(..., description="Specific pattern triggered")
    severity: str = Field(..., description="Severity weight of this pattern: low, medium, high, critical")
    description: str = Field(..., description="Human explanation of what this pattern identifies")
    snippet: Optional[str] = Field(None, description="Matched sanitized excerpt")


class AnalyzeRequest(BaseModel):
    content: str = Field(
        ...,
        min_length=1,
        max_length=20000,
        description="Untrusted content (email or webpage body) to analyze"
    )
    input_type: InputType = Field(
        default=InputType.EMAIL,
        description="Type of input content: email or webpage"
    )
    sender_email: Optional[str] = Field(
        default=None,
        max_length=320,
        description=(
            "Sender email address (required for domain verification on email type input). "
            "If omitted, domain check returns INVALID status and no score adjustment is applied."
        ),
    )

    @field_validator("content")
    @classmethod
    def content_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("content must not be blank or whitespace-only")
        return v


class DomainCheckInfo(BaseModel):
    """Domain verification result returned alongside the content analysis verdict."""
    sender_email: str = Field(..., description="Submitted sender address (may be empty if not provided)")
    sender_domain: str = Field(..., description="Extracted domain, or empty string if extraction failed")
    domain_status: str = Field(..., description="TRUSTED | UNKNOWN | SUSPICIOUS | INVALID")
    domain_reason: str = Field(..., description="Human-readable explanation of the domain verdict")
    risk_adjustment: int = Field(..., description="Score delta applied to content risk (-10..+20)")


class AnalyzeResponse(BaseModel):
    request_id: str
    input_type: InputType
    risk_score: int = Field(..., ge=0, le=100, description="Composite risk score from 0 to 100")
    risk_level: RiskLevel
    recommended_action: RecommendedAction
    reasons: List[str]
    reason_codes: List[str]
    classifier_source: str
    detection_methods: str = Field(default="rules", description="rules, semantic_classifier, or combined")
    detected_patterns: List[PatternMatchDetail]
    sanitized_text: Optional[str] = None
    processing_time_ms: float
    domain_check: Optional[DomainCheckInfo] = Field(
        default=None,
        description="Sender domain verification result (present when sender_email was provided or input_type is email)"
    )


class SummarizeRequest(BaseModel):
    content: str = Field(
        ...,
        min_length=1,
        max_length=20000,
        description="Content to summarize after passing firewall inspection"
    )
    input_type: InputType = Field(default=InputType.EMAIL)
    request_id: Optional[str] = Field(
        default=None,
        description="Optional ID of prior analyze request"
    )


class SummarizeResponse(BaseModel):
    request_id: str
    status: str = Field(..., description="success or blocked")
    risk_score: int
    risk_level: RiskLevel
    recommended_action: RecommendedAction
    summary: Optional[str] = None
    key_points: Optional[List[str]] = None
    summarizer_mode: str
    message: str
    processing_time_ms: float


class DashboardStats(BaseModel):
    total_analyses: int
    low_risk_count: int
    medium_risk_count: int
    high_risk_count: int
    blocked_count: int
    allowed_count: int
    avg_risk_score: float
    clean_ratio_pct: float
    category_breakdown: Dict[str, int]


class AuditLogEntry(BaseModel):
    request_id: str
    timestamp: str
    input_type: str
    content_length: int
    content_preview: str
    risk_score: int
    risk_level: str
    reason_codes: List[str]
    recommended_action: str
    final_action: str
    classifier_source: str
    processing_time_ms: float


class AuditLogResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[AuditLogEntry]


class HealthResponse(BaseModel):
    status: str
    version: str
    ai_provider_configured: bool
    ai_provider_name: str
    database_connected: bool
