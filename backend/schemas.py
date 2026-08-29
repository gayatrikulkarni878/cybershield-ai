from pydantic import BaseModel
from typing import List, Literal

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ThreatReport(BaseModel):
    input_type: str          # "url" | "message" | "qr"
    input_value: str
    risk_level: RiskLevel
    risk_score: int          # 0-100
    threat_type: str
    indicators: List[str]
    explanation: str
    recommended_action: str


class URLRequest(BaseModel):
    url: str


class MessageRequest(BaseModel):
    text: str
