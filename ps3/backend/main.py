"""
FastAPI Application Entry Point for PS3 Prompt-Injection Firewall.
Provides REST endpoints for content inspection, sandboxed summarization,
security dashboard analytics, and audit logs.
"""

import time
import uuid
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.config import (
    APP_ENV,
    MAX_INPUT_BYTES,
    AI_PROVIDER,
    AI_PROVIDER_API_KEY,
)
from backend.database import init_db
from backend.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    SummarizeRequest,
    SummarizeResponse,
    DashboardStats,
    AuditLogResponse,
    HealthResponse,
    RiskLevel,
    RecommendedAction,
    DomainCheckInfo,
)
from backend.detection import engine
from backend.policy import evaluate_policy, enforce_summarization_gate
from backend.summarizer import generate_summary
from backend.audit import record_audit_event, get_dashboard_stats, query_audit_logs
from backend.domain_check import check_sender_domain
from backend.config import RISK_THRESHOLD_MEDIUM, RISK_THRESHOLD_HIGH

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database schema on startup
    init_db()
    yield


app = FastAPI(
    title="Prompt-Injection Firewall API",
    description="Backend security layer inspecting untrusted content and safeguarding AI pipelines.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if APP_ENV == "development" else None,
    redoc_url=None,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """
    Enforces maximum payload size limit to prevent Denial of Service via oversized payloads.
    """
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_INPUT_BYTES:
                return JSONResponse(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    content={
                        "error": "PAYLOAD_TOO_LARGE",
                        "message": f"Payload exceeds maximum allowed limit of {MAX_INPUT_BYTES} bytes.",
                    },
                )
        except ValueError:
            pass
    return await call_next(request)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Prevents sensitive internal stack traces or configuration leaks from reaching clients.
    """
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred while processing the security request.",
        },
    )


# --- API Routes ---


@app.get("/health", response_model=HealthResponse, tags=["System"])
def get_health():
    """
    Service health probe without exposing sensitive keys or credentials.
    """
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        ai_provider_configured=bool(AI_PROVIDER_API_KEY and AI_PROVIDER != "none"),
        ai_provider_name=AI_PROVIDER if AI_PROVIDER_API_KEY else "local_safe_demo",
        database_connected=True,
    )


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Firewall"])
def analyze_content(req: AnalyzeRequest):
    """
    Analyzes untrusted email or webpage text for prompt-injection attacks.
    When analyzing email content, also performs sender domain verification
    and combines domain status with content analysis in the final score.
    Returns risk score, risk level, explainable reasons, recommended action,
    and full domain check details.
    Never persists raw confidential content.
    """
    start_time = time.perf_counter()
    request_id = str(uuid.uuid4())

    # 1. Run content detection engine
    result = engine.analyze(req.content, input_type=req.input_type.value)

    # 2. Run sender domain verification (always executed for email; also for
    #    webpage if sender_email is supplied)
    domain_result = check_sender_domain(
        req.sender_email if req.sender_email else None
    )

    # 3. Combine content risk score with domain adjustment
    #    - TRUSTED domain: mild downward adjustment (-10)
    #    - SUSPICIOUS domain: significant upward adjustment (+20)
    #    - INVALID / UNKNOWN: neutral (0) or very mild (+5)
    #    A trusted domain CANNOT suppress a HIGH-risk content verdict below the
    #    HIGH threshold — score is clamped but risk_level recomputed honestly.
    raw_content_score = result["risk_score"]
    adjusted_score = raw_content_score + domain_result.risk_adjustment
    final_score = max(0, min(100, adjusted_score))

    # Recompute risk level from the adjusted score
    if final_score >= RISK_THRESHOLD_HIGH:
        final_level = RiskLevel.HIGH
    elif final_score >= RISK_THRESHOLD_MEDIUM:
        final_level = RiskLevel.MEDIUM
    else:
        final_level = RiskLevel.LOW

    # Preserve original result dict but override score/level with adjusted values
    result["risk_score"] = final_score
    result["risk_level"] = final_level

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # 4. Policy evaluation on adjusted verdict
    is_allowed, recommended_action, _ = evaluate_policy(result)
    final_action = "ALLOWED" if is_allowed else "BLOCKED"

    # 5. Record audit metadata in SQLite
    record_audit_event(
        request_id=request_id,
        input_type=req.input_type.value,
        raw_content=req.content,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"].value,
        reason_codes=result["reason_codes"],
        recommended_action=recommended_action.value,
        final_action=final_action,
        classifier_source=result["classifier_source"],
        processing_time_ms=elapsed_ms,
    )

    # 6. Build domain_check response object
    domain_check_info = DomainCheckInfo(
        sender_email=domain_result.sender_email,
        sender_domain=domain_result.sender_domain,
        domain_status=domain_result.domain_status,
        domain_reason=domain_result.domain_reason,
        risk_adjustment=domain_result.risk_adjustment,
    )

    return AnalyzeResponse(
        request_id=request_id,
        input_type=req.input_type,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        recommended_action=recommended_action,
        reasons=result["reasons"],
        reason_codes=result["reason_codes"],
        classifier_source=result["classifier_source"],
        detection_methods=result.get("detection_methods", "rules"),
        detected_patterns=result["detected_patterns"],
        sanitized_text=result["sanitized_text"],
        processing_time_ms=round(elapsed_ms, 2),
        domain_check=domain_check_info,
    )


@app.post("/summarize", response_model=SummarizeResponse, tags=["Firewall & AI Agent"])
async def summarize_content(req: SummarizeRequest):
    """
    Safely summarizes permitted content.
    ENFORCES MANDATORY BACKEND SECURITY GATE: Re-evaluates content on backend.
    If content is flagged HIGH risk, summarization is strictly BLOCKED with 403 Forbidden.
    """
    start_time = time.perf_counter()
    request_id = req.request_id or str(uuid.uuid4())

    # Independent backend policy enforcement
    is_allowed, detection_result, decision_msg = enforce_summarization_gate(
        req.content, input_type=req.input_type.value
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    if not is_allowed:
        # Record blocked audit event
        record_audit_event(
            request_id=request_id,
            input_type=req.input_type.value,
            raw_content=req.content,
            risk_score=detection_result["risk_score"],
            risk_level=detection_result["risk_level"].value,
            reason_codes=detection_result["reason_codes"],
            recommended_action=RecommendedAction.BLOCK.value,
            final_action="BLOCKED",
            classifier_source="rules",
            processing_time_ms=elapsed_ms,
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "request_id": request_id,
                "status": "blocked",
                "risk_score": detection_result["risk_score"],
                "risk_level": detection_result["risk_level"].value,
                "recommended_action": RecommendedAction.BLOCK.value,
                "message": (
                    "Firewall Security Block: Content contains high-risk prompt injection directives. "
                    "Summarization was strictly denied to protect downstream AI systems."
                ),
                "reasons": detection_result["reasons"],
            },
        )

    # Content passed security gate -> proceed to sandboxed summarizer
    summary_result = await generate_summary(req.content)
    total_elapsed_ms = (time.perf_counter() - start_time) * 1000

    # Record summarized audit entry
    record_audit_event(
        request_id=request_id,
        input_type=req.input_type.value,
        raw_content=req.content,
        risk_score=detection_result["risk_score"],
        risk_level=detection_result["risk_level"].value,
        reason_codes=detection_result["reason_codes"],
        recommended_action=detection_result["recommended_action"].value,
        final_action="SUMMARIZED",
        classifier_source=detection_result["classifier_source"],
        processing_time_ms=total_elapsed_ms,
    )

    return SummarizeResponse(
        request_id=request_id,
        status="success",
        risk_score=detection_result["risk_score"],
        risk_level=detection_result["risk_level"],
        recommended_action=detection_result["recommended_action"],
        summary=summary_result["summary"],
        key_points=summary_result["key_points"],
        summarizer_mode=summary_result["mode"],
        message=f"Content cleared by firewall. {summary_result['note']}",
        processing_time_ms=round(total_elapsed_ms, 2),
    )


@app.get("/dashboard/stats", response_model=DashboardStats, tags=["Dashboard"])
def get_stats():
    """
    Returns real aggregate metrics calculated from SQLite audit history.
    """
    return get_dashboard_stats()


@app.get("/logs", response_model=AuditLogResponse, tags=["Dashboard"])
def get_logs(
    limit: int = 20,
    offset: int = 0,
    risk_level: str = None,
    input_type: str = None,
):
    """
    Returns paginated audit events without exposing sensitive raw text or keys.
    """
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Limit must be between 1 and 100.",
        )
    if offset < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Offset must be non-negative.",
        )

    total, entries = query_audit_logs(
        limit=limit,
        offset=offset,
        risk_level=risk_level,
        input_type=input_type,
    )

    return AuditLogResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=entries,
    )


# Mount frontend static assets if the folder exists
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    def serve_frontend():
        return FileResponse(FRONTEND_DIR / "index.html")
