"""Pydantic request/response models.

Strict validation:
  - `extra="forbid"` rejects unknown fields (defense against payload smuggling).
  - Every string is length-bounded and the list is item-count-bounded so
    abusive payloads are refused at the boundary rather than downstream.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

MAX_SENDER_LEN = 320
MAX_SUBJECT_LEN = 2048
MAX_BODY_LEN = 200_000
MAX_LINK_LEN = 4096
MAX_LINKS = 500
MAX_REASONING_LEN = 2000

MAX_ATTACHMENTS = 50
MAX_FILENAME_LEN = 255
MAX_CONTENT_TYPE_LEN = 255
SHA256_HEX_LEN = 64

LinkStr = Annotated[str, StringConstraints(max_length=MAX_LINK_LEN)]

Verdict = Literal["Safe", "Low Risk", "Suspicious", "High Risk", "Malicious"]


class AttachmentInfo(BaseModel):
    """Metadata for one email attachment. Hash is computed client-side
    (in Apps Script) so we never receive the file contents."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=MAX_FILENAME_LEN)
    # SHA-256 hex, lowercase. Pattern is the strict shape — anything else is rejected.
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size: int = Field(ge=0)
    content_type: str = Field(default="", max_length=MAX_CONTENT_TYPE_LEN)


class EmailAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sender: str = Field(min_length=1, max_length=MAX_SENDER_LEN)
    subject: str = Field(default="", max_length=MAX_SUBJECT_LEN)
    body: str = Field(default="", max_length=MAX_BODY_LEN)
    links: list[LinkStr] = Field(default_factory=list, max_length=MAX_LINKS)
    attachments: list[AttachmentInfo] = Field(
        default_factory=list, max_length=MAX_ATTACHMENTS
    )


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: int = Field(ge=0, le=100)
    verdict: Verdict
    reasoning: str = Field(min_length=1, max_length=MAX_REASONING_LEN)
