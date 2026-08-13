"""FastAPI boundary for streaming OCSF intake and Agent-oriented investigation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from secrets import compare_digest
from typing import Any, Literal
from uuid import uuid4

import pymysql
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import mock
from .adapters import SUPPORTED_SOURCE_FORMATS
from .ai_security import assess_ai_security_flow, mock_ai_security_assessment
from .config import get_settings
from .llm import OpenAICompatibleClient
from .repository import StarRocksRepository
from .service import SecurityGraphService

DemoMode = Literal["live", "mock"]
MODE_QUERY = Query(default="live")


class IngestRequest(BaseModel):
    tenant_id: str = Field(default="default", min_length=1, max_length=128)
    events: list[dict[str, Any]] = Field(min_length=1, max_length=10_000)
    mode: DemoMode = "live"


class DemoRequest(BaseModel):
    tenant_id: str = Field(default="demo", min_length=1, max_length=128)
    run_id: str | None = Field(default=None, min_length=1, max_length=64)
    mode: DemoMode = "live"
    scenario: str = Field(default=mock.DEFAULT_SCENARIO, min_length=1, max_length=64)


class ConnectionTestRequest(BaseModel):
    """Ephemeral connection profile; credentials are never persisted or returned."""

    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=9030, ge=1, le=65535)
    user: str = Field(default="root", min_length=1, max_length=128)
    password: str = Field(default="", max_length=2048)
    database: str = Field(default="security_lakehouse", min_length=1, max_length=128)
    connect_timeout_seconds: int = Field(default=5, ge=1, le=60)
    ssl_enabled: bool = False
    ssl_verify: bool = True


class DocumentRequest(BaseModel):
    tenant_id: str = Field(default="default", min_length=1, max_length=128)
    entity_id: str = Field(min_length=1, max_length=768)
    content: str = Field(min_length=1)
    chunk_id: str | None = Field(default=None, max_length=128)
    mode: DemoMode = "live"
    extract_graph: bool = True
    text_extractor: Literal["rules", "llm"] = "rules"


class TextGraphExtractionRequest(BaseModel):
    tenant_id: str = Field(default="default", min_length=1, max_length=128)
    content: str = Field(default="", max_length=100_000)
    source_id: str | None = Field(default=None, min_length=1, max_length=96)
    source_type: str = Field(default="security_report", min_length=1, max_length=64)
    extractor: Literal["rules", "llm"] = "rules"
    persist: bool = True
    mode: DemoMode = "live"
    scenario: str = Field(default=mock.DEFAULT_SCENARIO, min_length=1, max_length=64)


class TextGraphReviewRequest(BaseModel):
    tenant_id: str = Field(default="default", min_length=1, max_length=128)
    decision: Literal["approved", "rejected", "needs_context"]
    reviewer: str = Field(min_length=1, max_length=256)
    note: str = Field(default="", max_length=4_000)
    mode: DemoMode = "live"


class InvestigationRequest(BaseModel):
    tenant_id: str = Field(default="default", min_length=1, max_length=128)
    entity_id: str = Field(min_length=1, max_length=768)
    question: str = Field(default="", max_length=20_000)
    depth: int | None = Field(default=None, ge=1, le=3)
    limit: int = Field(default=50, ge=1, le=200)
    mode: DemoMode = "live"
    scenario: str = Field(default=mock.DEFAULT_SCENARIO, min_length=1, max_length=64)
    use_llm: bool = False


class RetrospectiveAnalysisRequest(BaseModel):
    """Bounded post-incident analysis request over already-ingested OCSF history."""

    tenant_id: str = Field(default="default", min_length=1, max_length=128)
    start_time: datetime | None = None
    end_time: datetime | None = None
    lookback_hours: int = Field(default=168, ge=1, le=24 * 90)
    baseline_hours: int = Field(default=24 * 30, ge=0, le=24 * 365)
    session_gap_minutes: int = Field(default=30, ge=1, le=240)
    max_events: int = Field(default=20_000, ge=100, le=50_000)
    cluster_limit: int = Field(default=12, ge=1, le=50)
    mode: DemoMode = "live"
    scenario: str = Field(default=mock.DEFAULT_SCENARIO, min_length=1, max_length=64)


class LLMTestRequest(BaseModel):
    """Ephemeral OpenAI-compatible profile; API keys are never persisted or returned."""

    api_base: str = Field(min_length=8, max_length=1024)
    api_key: str = Field(min_length=1, max_length=2048)
    model: str = Field(min_length=1, max_length=256)
    timeout_seconds: int = Field(default=45, ge=1, le=300)


class AISecurityAssessmentRequest(BaseModel):
    """Assess a customer AI App/RAG/Agent interaction at the product boundary."""

    tenant_id: str = Field(default="default", min_length=1, max_length=128)
    app_id: str = Field(default="default-ai-app", min_length=1, max_length=128)
    user_role: str = Field(default="user", min_length=1, max_length=128)
    prompt: str = Field(default="", max_length=50_000)
    rag_context: list[dict[str, Any]] = Field(default_factory=list, max_length=50)
    tool_call: dict[str, Any] | None = None
    model_output: str = Field(default="", max_length=50_000)
    mode: DemoMode = "live"


@lru_cache
def get_service() -> SecurityGraphService:
    settings = get_settings()
    return SecurityGraphService(StarRocksRepository(settings), settings)


app = FastAPI(
    title="SentinelGraph",
    version="0.1.0",
    description=(
        "Versioned REST API for OCSF intake, StarRocks graph correlation, security detections, "
        "text-to-graph enrichment, and evidence-bounded Agent investigations. "
        "See /integrations for third-party integration guidance."
    ),
    openapi_tags=[
        {"name": "Integration", "description": "Capability discovery for third-party callers."},
        {"name": "Ingestion", "description": "OCSF and source-adapter event intake."},
        {"name": "Investigation", "description": "Alerts, graph context, and Agent evidence."},
        {
            "name": "Retrospective",
            "description": "Bounded historical behavior clustering and evidence-led post-analysis.",
        },
        {"name": "Text Graph", "description": "Reviewable text-to-graph enrichment."},
        {
            "name": "AI Security",
            "description": "Customer AI App, RAG, and Agent guardrail assessment.",
        },
    ],
)
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def require_integration_api_key(request: Request, call_next: Any) -> Any:
    """Protect /v1 only when the operator explicitly configures integration keys."""
    configured_keys = get_settings().integration_api_key_set
    if request.url.path.startswith("/v1/") and configured_keys:
        provided_key = request.headers.get("X-API-Key", "")
        if not any(compare_digest(provided_key, key) for key in configured_keys):
            return JSONResponse(
                status_code=401,
                content={
                    "detail": "missing or invalid X-API-Key",
                    "code": "authentication_failed",
                },
                headers={"WWW-Authenticate": "ApiKey"},
            )
    return await call_next(request)


def custom_openapi() -> dict[str, Any]:
    """Advertise the optional integration header in generated OpenAPI clients."""
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["IntegrationApiKey"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
        "description": "Required for /v1 when INTEGRATION_API_KEYS is configured by the operator.",
    }
    for path, methods in schema.get("paths", {}).items():
        if path.startswith("/v1/"):
            for operation in methods.values():
                if isinstance(operation, dict):
                    operation["security"] = [{"IntegrationApiKey": []}]
    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi


@app.get("/", include_in_schema=False)
def demo_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/integrations", include_in_schema=False)
def integrations_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "integrations.html")


@app.get("/guide", include_in_schema=False)
def project_guide_page() -> FileResponse:
    """Human-readable project background and concepts, kept aligned with README."""
    return FileResponse(STATIC_DIR / "guide.html")


@app.get("/health")
def health(mode: DemoMode = MODE_QUERY) -> dict[str, str]:
    if mode == "mock":
        return {"status": "ok", "mode": "mock"}
    try:
        get_service().repository.ping()
    except Exception as error:  # health endpoint must return a usable diagnostic
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error
    return {"status": "ok", "mode": "live"}


@app.get("/v1/system/connection")
def active_connection(mode: DemoMode = MODE_QUERY) -> dict[str, Any]:
    """Expose only non-secret connection metadata for the operator console."""
    if mode == "mock":
        return mock.connection()
    return {"active": get_service().repository.connection_info()}


@app.get("/v1/integration/capabilities", tags=["Integration"])
def integration_capabilities() -> dict[str, Any]:
    """Stable discovery document for API clients and connector installers."""
    settings = get_settings()
    return {
        "api_version": "v1",
        "openapi_url": "/openapi.json",
        "interactive_docs_url": "/docs",
        "integration_guide_url": "/integrations",
        "authentication": {
            "scheme": "X-API-Key",
            "required": bool(settings.integration_api_key_set),
        },
        "capabilities": {
            "ocsf_ingest": True,
            "source_adapters": sorted(SUPPORTED_SOURCE_FORMATS),
            "graph_context": True,
            "detections": True,
            "retrospective_analysis": True,
            "text_to_graph": True,
            "agent_investigation": True,
            "ai_security": {
                "input_guardrails": True,
                "rag_access_control": True,
                "agent_tool_approval": True,
                "data_loss_prevention": True,
                "audit_chain": True,
            },
            "mock_mode": True,
        },
    }


@app.post("/v1/system/connection/test")
def test_connection(request: ConnectionTestRequest) -> dict[str, Any]:
    """Test a third-party StarRocks target without changing the running profile."""
    settings = get_settings().model_copy(
        update={
            "starrocks_host": request.host,
            "starrocks_port": request.port,
            "starrocks_user": request.user,
            "starrocks_password": request.password,
            "starrocks_database": request.database,
            "starrocks_connect_timeout_seconds": request.connect_timeout_seconds,
            "starrocks_ssl_enabled": request.ssl_enabled,
            "starrocks_ssl_verify": request.ssl_verify,
        }
    )
    try:
        return StarRocksRepository(settings).diagnose()
    except Exception as error:
        raise HTTPException(status_code=422, detail=f"connection failed: {error}") from error


@app.get("/v1/system/llm")
def active_llm() -> dict[str, Any]:
    """Expose active non-secret LLM metadata."""
    return OpenAICompatibleClient(get_settings()).info()


@app.post("/v1/system/llm/test")
def test_llm(request: LLMTestRequest) -> dict[str, Any]:
    """Test an OpenAI-compatible model endpoint without changing the running configuration."""
    settings = get_settings().model_copy(
        update={
            "llm_enabled": True,
            "llm_api_base": request.api_base,
            "llm_api_key": request.api_key,
            "llm_model": request.model,
            "llm_timeout_seconds": request.timeout_seconds,
        }
    )
    try:
        return OpenAICompatibleClient(settings).test()
    except Exception as error:
        raise HTTPException(status_code=422, detail=f"LLM connection failed: {error}") from error


@app.post("/v1/ai-security/assessments", tags=["AI Security"])
def assess_ai_security(request: AISecurityAssessmentRequest) -> dict[str, Any]:
    """Assess customer AI App, RAG, and Agent traffic at the product boundary."""
    if request.mode == "mock":
        return {"mode": "mock", **mock_ai_security_assessment(request.tenant_id)}
    return {
        "mode": "live",
        **assess_ai_security_flow(
            tenant_id=request.tenant_id,
            app_id=request.app_id,
            user_role=request.user_role,
            prompt=request.prompt,
            rag_context=request.rag_context,
            tool_call=request.tool_call,
            model_output=request.model_output,
        ),
    }


@app.post("/v1/events", status_code=202)
def ingest_events(request: IngestRequest) -> dict[str, Any]:
    if request.mode == "mock":
        return {"accepted": len(request.events), "tenant_id": request.tenant_id, "mode": "mock"}
    try:
        count = get_service().ingest(request.events, request.tenant_id)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except pymysql.MySQLError as error:
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error
    return {"accepted": count, "tenant_id": request.tenant_id, "mode": "live"}


@app.post("/v1/ingest/{source_format}", status_code=202)
def ingest_source(source_format: str, request: IngestRequest) -> dict[str, Any]:
    try:
        if source_format not in SUPPORTED_SOURCE_FORMATS:
            raise ValueError(f"unsupported source format: {source_format}")
        if request.mode == "mock":
            return {
                "accepted": len(request.events),
                "tenant_id": request.tenant_id,
                "source_format": source_format,
                "mode": "mock",
            }
        count = get_service().ingest_source(request.events, source_format, request.tenant_id)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except pymysql.MySQLError as error:
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error
    return {
        "accepted": count,
        "tenant_id": request.tenant_id,
        "source_format": source_format,
        "mode": "live",
    }


@app.post("/v1/demo/load")
def load_demo(request: DemoRequest) -> dict[str, Any]:
    if request.mode == "mock":
        try:
            return mock.load_demo(request.tenant_id, request.run_id, request.scenario)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
    if not get_settings().demo_enabled:
        raise HTTPException(status_code=403, detail="demo endpoint is disabled")
    try:
        return get_service().load_demo(request.tenant_id, request.run_id)
    except pymysql.MySQLError as error:
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error


@app.get("/v1/demo/scenarios")
def list_demo_scenarios() -> dict[str, Any]:
    """Expose the offline scenario catalogue used by the customer demo console."""
    return mock.list_scenarios()


@app.post("/v1/detections/run")
def run_detections(
    tenant_id: str = Query(default="default", min_length=1, max_length=128),
    scenario: str = Query(default=mock.DEFAULT_SCENARIO, min_length=1, max_length=64),
    mode: DemoMode = MODE_QUERY,
) -> dict[str, Any]:
    if mode == "mock":
        try:
            results = mock.alerts(tenant_id, scenario)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return {"created": len(results["alerts"]), **results}
    try:
        alerts = get_service().run_detections(tenant_id)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except pymysql.MySQLError as error:
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error
    return {"created": len(alerts), "alerts": alerts, "mode": "live"}


@app.get("/v1/alerts")
def list_alerts(
    tenant_id: str = Query(default="default", min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=1000),
    scenario: str = Query(default=mock.DEFAULT_SCENARIO, min_length=1, max_length=64),
    mode: DemoMode = MODE_QUERY,
) -> dict[str, Any]:
    if mode == "mock":
        try:
            return mock.alerts(tenant_id, scenario)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
    try:
        return {"alerts": get_service().repository.list_alerts(tenant_id, limit), "mode": "live"}
    except pymysql.MySQLError as error:
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error


def _utc_naive(value: datetime) -> datetime:
    """Keep MySQL-compatible timestamp parameters unambiguous at the API boundary."""
    if value.tzinfo:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


@app.post("/v1/retrospective/analyses", tags=["Retrospective"])
def analyze_history(request: RetrospectiveAnalysisRequest) -> dict[str, Any]:
    """Cluster a bounded historical OCSF slice for explainable post-incident investigation."""
    if request.mode == "mock":
        try:
            return mock.retrospective(request.tenant_id, request.scenario)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    end_time = (
        _utc_naive(request.end_time) if request.end_time else datetime.now(UTC).replace(tzinfo=None)
    )
    start_time = (
        _utc_naive(request.start_time)
        if request.start_time
        else end_time - timedelta(hours=request.lookback_hours)
    )
    if end_time <= start_time:
        raise HTTPException(status_code=422, detail="end_time must be after start_time")
    baseline_start = start_time - timedelta(hours=request.baseline_hours)
    try:
        return get_service().analyze_history(
            tenant_id=request.tenant_id,
            start_time=start_time,
            end_time=end_time,
            baseline_start_time=baseline_start,
            session_gap_minutes=request.session_gap_minutes,
            max_events=request.max_events,
            cluster_limit=request.cluster_limit,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except pymysql.MySQLError as error:
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error


@app.get("/v1/graph/{entity_id}")
def graph(
    entity_id: str,
    tenant_id: str = Query(default="default", min_length=1, max_length=128),
    depth: int = Query(default=2, ge=1, le=3),
    limit: int = Query(default=200, ge=1, le=1000),
    scenario: str = Query(default=mock.DEFAULT_SCENARIO, min_length=1, max_length=64),
    mode: DemoMode = MODE_QUERY,
) -> dict[str, Any]:
    if mode == "mock":
        try:
            return mock.graph(entity_id, tenant_id, depth, scenario)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
    try:
        return get_service().repository.graph_context(entity_id, tenant_id, depth, limit)
    except pymysql.MySQLError as error:
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error


@app.post("/v1/rag/documents", status_code=201)
def add_document(request: DocumentRequest) -> dict[str, Any]:
    if request.mode == "mock":
        return {
            "chunk_id": request.chunk_id or "mock-document",
            "mode": "mock",
            "text_graph": mock.text_graph(request.tenant_id),
        }
    try:
        chunk_id = request.chunk_id or ""
        if not chunk_id:
            # Use one stable identifier for the vector document and its graph provenance.
            chunk_id = uuid4().hex
        text_graph: dict[str, Any] | None = None
        if request.extract_graph:
            text_graph = get_service().extract_text_graph(
                request.content,
                request.tenant_id,
                source_id=chunk_id,
                source_type="security_document",
                extractor=request.text_extractor,
                persist=True,
            )
        chunk_id = get_service().add_document(
            request.content, request.tenant_id, request.entity_id, chunk_id
        )
    except (ValueError, pymysql.MySQLError) as error:
        status_code = 422 if isinstance(error, ValueError) else 503
        raise HTTPException(status_code=status_code, detail=str(error)) from error
    return {
        "chunk_id": chunk_id,
        "mode": "live",
        "text_graph": text_graph,
    }


@app.post("/v1/text-graph/extract")
def extract_text_graph(request: TextGraphExtractionRequest) -> dict[str, Any]:
    """Extract reviewable security indicators and relations from a text source."""
    if request.mode == "mock":
        try:
            return mock.text_graph(request.tenant_id, request.scenario)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
    if not request.content.strip():
        raise HTTPException(status_code=422, detail="content must not be empty in live mode")
    try:
        return get_service().extract_text_graph(
            request.content,
            request.tenant_id,
            source_id=request.source_id,
            source_type=request.source_type,
            extractor=request.extractor,
            persist=request.persist,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except pymysql.MySQLError as error:
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error


@app.get("/v1/text-graph/extractions")
def list_text_graph_extractions(
    tenant_id: str = Query(default="default", min_length=1, max_length=128),
    source_id: str | None = Query(default=None, min_length=1, max_length=96),
    limit: int = Query(default=100, ge=1, le=1_000),
    scenario: str = Query(default=mock.DEFAULT_SCENARIO, min_length=1, max_length=64),
    mode: DemoMode = MODE_QUERY,
) -> dict[str, Any]:
    if mode == "mock":
        try:
            preview = mock.text_graph(tenant_id, scenario)
            return {"mode": "mock", "extractions": preview["relations"], "persisted": False}
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
    try:
        return {
            "mode": "live",
            "extractions": get_service().repository.list_text_graph_extractions(
                tenant_id, source_id, limit
            ),
        }
    except pymysql.MySQLError as error:
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error


@app.post("/v1/text-graph/extractions/{extraction_id}/review", status_code=201)
def review_text_graph_extraction(
    extraction_id: str,
    request: TextGraphReviewRequest,
) -> dict[str, Any]:
    if request.mode == "mock":
        return {
            "mode": "mock",
            "persisted": False,
            "message": "Mock extractions are previews and cannot create a review record.",
        }
    try:
        get_service().repository.record_text_graph_review(
            extraction_id, request.tenant_id, request.decision, request.reviewer, request.note
        )
    except pymysql.MySQLError as error:
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error
    return {"mode": "live", "extraction_id": extraction_id, "decision": request.decision}


@app.post("/v1/agent/investigations")
def investigate(request: InvestigationRequest) -> dict[str, Any]:
    try:
        if request.mode == "mock":
            return mock.investigation(
                request.entity_id,
                request.question,
                request.tenant_id,
                request.depth or 2,
                request.scenario,
            )
        investigation = get_service().investigate(
            request.entity_id, request.question, request.tenant_id, request.depth, request.limit
        )
        if request.use_llm:
            investigation["llm"] = OpenAICompatibleClient(get_settings()).investigate(investigation)
        investigation["mode"] = "live"
        return investigation
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except pymysql.MySQLError as error:
        raise HTTPException(status_code=503, detail=f"StarRocks unavailable: {error}") from error
