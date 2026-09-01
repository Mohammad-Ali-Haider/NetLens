from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

State = Literal["queued", "running", "succeeded", "failed"]
ProviderName = Literal["mock", "openai", "anthropic", "ollama"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class ErrorDetail(StrictModel):
    code: str
    message: str


class ErrorResponse(StrictModel):
    error: ErrorDetail


class Health(StrictModel):
    status: str


class CaptureOut(StrictModel):
    id: str
    filename: str
    size_bytes: int
    sha256: str
    format: str
    packet_count: int
    warnings: list[str]
    created_at: datetime


class AnalysisIn(StrictModel):
    capture_id: str = Field(min_length=1, max_length=36, examples=["capture-uuid"])
    dns_slow_ms: float | None = Field(None, gt=0, le=60_000, examples=[250])


class ReportIn(StrictModel):
    provider: ProviderName = "mock"


class Finding(StrictModel):
    id: str
    detector: str
    detector_version: str = "1.0.0"
    severity: Literal["info", "warning", "error"]
    observation: str
    measurements: dict[str, Any]
    packet_refs: list[Annotated[int, Field(ge=1)]] = Field(min_length=1)
    limitations: list[str]
    alternatives: list[str]


class Conversation(StrictModel):
    protocol: str
    endpoints: list[str]
    packets: int
    captured_bytes: int


class TrafficStats(StrictModel):
    total_packets: int
    captured_bytes: int
    duration_seconds: float
    protocols: dict[str, int]
    top_sources: dict[str, int]
    top_destinations: dict[str, int]
    conversations: list[Conversation]
    dns_requests: int
    dns_responses: int
    dns_matched_responses: int
    warnings: list[str]


class OperationOut(StrictModel):
    id: str
    status: State
    status_url: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    attempts: int
    error_code: str | None


class AnalysisOut(OperationOut):
    capture_id: str
    statistics: TrafficStats | None


class ObservedIssue(StrictModel):
    finding_ids: list[str] = Field(min_length=1, max_length=100)
    explanation: str = Field(min_length=1, max_length=2000)


class Hypothesis(StrictModel):
    finding_ids: list[str] = Field(min_length=1, max_length=100)
    possibility: str = Field(min_length=1, max_length=2000)
    uncertainty: str = Field(min_length=1, max_length=1000)


class ReportContent(StrictModel):
    summary: str = Field(min_length=1, max_length=4000)
    observed_issues: list[ObservedIssue] = Field(max_length=100)
    hypotheses: list[Hypothesis] = Field(max_length=100)
    next_checks: list[str] = Field(max_length=30)
    evidence_limitations: list[str] = Field(min_length=1, max_length=30)


class ProviderMetadata(StrictModel):
    provider: str
    model: str
    prompt_version: str
    latency_ms: float
    usage: dict[str, int] | None = None
    estimated_cost_usd: float | None = None
    fallback_from: str | None = None


class ReportOut(OperationOut):
    analysis_id: str
    provider: str
    content: ReportContent | None
    provider_metadata: ProviderMetadata | None


class FindingsPage(StrictModel):
    items: list[Finding]
    total: int
    offset: int
    limit: int
