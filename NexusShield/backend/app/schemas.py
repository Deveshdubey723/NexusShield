from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class MessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=50_000)
    save_content: bool = False


class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2_048)
    save_content: bool = False


class EmailRequest(BaseModel):
    subject: str = Field(default="", max_length=300)
    body: str = Field(default="", max_length=50_000)
    sender: str = Field(default="", max_length=320)
    reply_to: str = Field(default="", max_length=320)
    link_text: str = Field(default="", max_length=2_048)
    save_content: bool = False

    @model_validator(mode="after")
    def require_email_content(self):
        if not any((self.subject.strip(), self.body.strip(), self.sender.strip(), self.link_text.strip())):
            raise ValueError("Provide an email subject, body, sender, or link text.")
        return self


class DocumentSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=200)


class SecurityNoteRequest(BaseModel):
    note: str = Field(min_length=1, max_length=2_000)


class AnalysisResult(BaseModel):
    scan_id: int | None = None
    scan_type: Literal["message", "url", "email"]
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["low", "medium", "high"]
    verdict: Literal["low_risk", "suspicious", "high_risk"]
    detected_signals: list[str]
    evidence: list[str]
    explanation: str
    recommended_actions: list[str]
    analysis_limitations: list[str]
    reasons: list[str]
    indicators: list[str]
    content_saved: bool = False


class PrivacySettings(BaseModel):
    save_scan_content: bool = False


class HistoryItem(BaseModel):
    id: int
    scan_type: str
    risk_score: int
    risk_level: Literal["low", "medium", "high"]
    verdict: str
    created_at: str


class DashboardStats(BaseModel):
    total_scans: int
    high_risk_scans: int
    suspicious_scans: int
    low_risk_scans: int
    scans_by_type: dict[str, int]
    indexed_documents: int = 0
    trend: list[dict[str, int | str]] = Field(default_factory=list)


class DocumentSearchResult(BaseModel):
    document_id: str
    filename: str
    snippet: str
    rank: int
    page_number: int | None = None


class SecurityNote(BaseModel):
    id: int
    note: str
    created_at: str


class IndexedDocument(BaseModel):
    id: str
    filename: str
    created_at: str
