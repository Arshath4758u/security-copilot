from typing import List, Literal

from pydantic import BaseModel, Field, field_validator


class Alert(BaseModel):
    id: str
    type: str
    user: str
    src_ip: str
    description: str


class TriageResult(BaseModel):
    """The JSON the LLM must return. Anything else fails validation and is retried."""
    severity: Literal["low", "medium", "high", "critical"]
    mitre_technique: str
    summary: str
    recommended_action: str
    confidence: float = Field(ge=0.0, le=1.0)
    false_positive: bool

    @field_validator("severity", mode="before")
    @classmethod
    def _lower(cls, v):
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("recommended_action", "summary", mode="before")
    @classmethod
    def _flatten(cls, v):
        # small models sometimes return a list of steps; join it into one string
        return "; ".join(map(str, v)) if isinstance(v, list) else v


class ComplianceAnswer(BaseModel):
    answer: str
    found: bool
    sources: List[str] = []
