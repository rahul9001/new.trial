"""
Audit and Statistics Management Service.
Handles privacy-preserving audit logging and aggregation for the security dashboard.
"""

import json
import hashlib
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from backend.database import get_db_connection
from backend.schemas import AuditLogEntry, DashboardStats


def sanitize_preview(raw_text: str, max_chars: int = 60) -> str:
    """
    Creates a brief, redacted preview string.
    Masks out likely tokens, keys, passwords, or emails.
    """
    cleaned = raw_text.strip().replace("\n", " ").replace("\r", " ")
    # Mask any potential API key or bearer token style sequences
    cleaned = re.sub(r"(sk-[a-zA-Z0-9_-]{10,}|bearer\s+[a-zA-Z0-9._-]+)", "[REDACTED_SECRET]", cleaned, flags=re.I)
    # Mask emails
    cleaned = re.sub(r"[\w\.-]+@[\w\.-]+\.\w+", "[REDACTED_EMAIL]", cleaned)
    if len(cleaned) > max_chars:
        return cleaned[:max_chars] + "..."
    return cleaned


def record_audit_event(
    request_id: str,
    input_type: str,
    raw_content: str,
    risk_score: int,
    risk_level: str,
    reason_codes: List[str],
    recommended_action: str,
    final_action: str,
    classifier_source: str,
    processing_time_ms: float,
) -> None:
    """
    Persists an audit log entry in SQLite.
    Never persists raw confidential content.
    Uses INSERT OR REPLACE to support updating requests and preventing unique conflicts.
    """
    content_hash = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
    content_preview = sanitize_preview(raw_content)
    timestamp = datetime.now(timezone.utc).isoformat()
    reason_codes_json = json.dumps(reason_codes)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO audit_logs (
                request_id, timestamp, input_type, content_length,
                content_hash, content_preview, risk_score, risk_level,
                reason_codes, recommended_action, final_action,
                classifier_source, processing_time_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                timestamp,
                input_type,
                len(raw_content),
                content_hash,
                content_preview,
                risk_score,
                risk_level,
                reason_codes_json,
                recommended_action,
                final_action,
                classifier_source,
                round(processing_time_ms, 2),
            ),
        )
        conn.commit()


def get_dashboard_stats() -> DashboardStats:
    """
    Calculates real backend-generated aggregated statistics for the security dashboard.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Total counts
        cursor.execute("SELECT COUNT(*) FROM audit_logs")
        total = cursor.fetchone()[0]

        if total == 0:
            return DashboardStats(
                total_analyses=0,
                low_risk_count=0,
                medium_risk_count=0,
                high_risk_count=0,
                blocked_count=0,
                allowed_count=0,
                avg_risk_score=0.0,
                clean_ratio_pct=100.0,
                category_breakdown={},
            )

        # Risk level counts
        cursor.execute("SELECT risk_level, COUNT(*) FROM audit_logs GROUP BY risk_level")
        level_counts = dict(cursor.fetchall())
        low_count = level_counts.get("LOW", 0)
        med_count = level_counts.get("MEDIUM", 0)
        high_count = level_counts.get("HIGH", 0)

        # Blocked vs Allowed counts
        cursor.execute("SELECT final_action, COUNT(*) FROM audit_logs GROUP BY final_action")
        action_counts = dict(cursor.fetchall())
        blocked_count = action_counts.get("BLOCKED", 0)
        allowed_count = total - blocked_count

        # Average risk score
        cursor.execute("SELECT AVG(risk_score) FROM audit_logs")
        avg_score_row = cursor.fetchone()
        avg_risk_score = round(float(avg_score_row[0]), 1) if avg_score_row and avg_score_row[0] is not None else 0.0

        # Clean ratio (low risk percentage)
        clean_ratio = round((low_count / total) * 100, 1)

        # Category breakdown from reason codes
        cursor.execute("SELECT reason_codes FROM audit_logs")
        rows = cursor.fetchall()
        category_breakdown: Dict[str, int] = {}
        for row in rows:
            try:
                codes = json.loads(row[0])
                for code in codes:
                    category_breakdown[code] = category_breakdown.get(code, 0) + 1
            except Exception:
                continue

        return DashboardStats(
            total_analyses=total,
            low_risk_count=low_count,
            medium_risk_count=med_count,
            high_risk_count=high_count,
            blocked_count=blocked_count,
            allowed_count=allowed_count,
            avg_risk_score=avg_risk_score,
            clean_ratio_pct=clean_ratio,
            category_breakdown=category_breakdown,
        )


def query_audit_logs(
    limit: int = 20,
    offset: int = 0,
    risk_level: Optional[str] = None,
    input_type: Optional[str] = None,
) -> Tuple[int, List[AuditLogEntry]]:
    """
    Retrieves filtered and paginated audit logs.
    """
    conditions = []
    params = []

    if risk_level and risk_level.upper() in ("LOW", "MEDIUM", "HIGH"):
        conditions.append("risk_level = ?")
        params.append(risk_level.upper())

    if input_type and input_type.lower() in ("email", "webpage"):
        conditions.append("input_type = ?")
        params.append(input_type.lower())

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Count total matches
        count_sql = f"SELECT COUNT(*) FROM audit_logs {where_clause}"
        cursor.execute(count_sql, params)
        total = cursor.fetchone()[0]

        # Fetch records
        query_sql = f"""
            SELECT request_id, timestamp, input_type, content_length,
                   content_preview, risk_score, risk_level, reason_codes,
                   recommended_action, final_action, classifier_source,
                   processing_time_ms
            FROM audit_logs
            {where_clause}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(query_sql, params + [min(100, max(1, limit)), max(0, offset)])
        rows = cursor.fetchall()

        entries = []
        for r in rows:
            try:
                codes = json.loads(r["reason_codes"])
            except Exception:
                codes = []

            entries.append(
                AuditLogEntry(
                    request_id=r["request_id"],
                    timestamp=r["timestamp"],
                    input_type=r["input_type"],
                    content_length=r["content_length"],
                    content_preview=r["content_preview"],
                    risk_score=r["risk_score"],
                    risk_level=r["risk_level"],
                    reason_codes=codes,
                    recommended_action=r["recommended_action"],
                    final_action=r["final_action"],
                    classifier_source=r["classifier_source"],
                    processing_time_ms=r["processing_time_ms"],
                )
            )

        return total, entries
