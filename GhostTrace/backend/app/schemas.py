"""Pydantic models — espelham src/lib/types/index.ts."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
VulnStatus = Literal["unfixed", "fixed", "retest", "wont_fix"]
Methodology = Literal["blackbox", "graybox", "whitebox"]
ProjectStatus = Literal["active", "paused", "reporting", "closed"]
EngagementType = Literal[
    "web_app",
    "network_internal",
    "network_external",
    "red_team",
    "mobile",
    "cloud",
    "bug_bounty",
]
ChainPrivilege = Literal["unauth", "user", "root"]


class ToolGroup(BaseModel):
    purpose: str
    tools: list[str]


class Project(BaseModel):
    id: str
    client: str
    codename: Optional[str] = None
    engagementType: EngagementType
    scope: list[str]
    methodology: Methodology
    startDate: str
    endDate: Optional[str] = None
    status: ProjectStatus
    notes: Optional[str] = None
    tools: Optional[list[ToolGroup]] = None
    createdAt: str
    updatedAt: str


class CVSS(BaseModel):
    vector: str
    score: float


class ReproStep(BaseModel):
    id: str
    order: int
    text: str
    command: Optional[str] = None
    screenshots: list[str] = Field(default_factory=list)


class ProofOfConcept(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    code: Optional[dict[str, str]] = None
    screenshots: list[str] = Field(default_factory=list)


class Vulnerability(BaseModel):
    id: str
    projectId: str
    number: Optional[int] = None
    title: str
    severity: Severity
    status: VulnStatus
    cvss: Optional[CVSS] = None
    cwe: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    description: str = ""
    attackScenario: str = ""
    recommendation: str = ""
    remediationNotes: Optional[str] = None
    additionalNotes: Optional[str] = None
    steps: list[ReproStep] = Field(default_factory=list)
    pocs: list[ProofOfConcept] = Field(default_factory=list)
    isZeroDay: Optional[bool] = None
    isEasilyExploitable: Optional[bool] = None
    createdAt: str
    updatedAt: str


class TimelineEvent(BaseModel):
    id: str
    projectId: str
    ts: str
    type: str
    host: Optional[str] = None
    target: Optional[str] = None
    title: str
    details: Optional[str] = None
    vulnerabilityId: Optional[str] = None
    attachments: Optional[list[str]] = None


class ChainStep(BaseModel):
    order: int
    action: str
    eventId: Optional[str] = None


class AttackChainNode(BaseModel):
    id: str
    projectId: str
    host: str
    ip: Optional[str] = None
    privilege: ChainPrivilege
    steps: list[ChainStep] = Field(default_factory=list)
    nextNodeIds: list[str] = Field(default_factory=list)


class Credential(BaseModel):
    id: str
    projectId: str
    user: str
    context: str
    value: str
    source: Optional[str] = None
    host: Optional[str] = None
    rotated: Optional[bool] = None


class Evidence(BaseModel):
    id: str
    projectId: str
    filename: str
    mime: str
    size: int
    uploadedAt: str
    vulnerabilityIds: list[str] = Field(default_factory=list)
    thumbnailUrl: Optional[str] = None
    caption: Optional[str] = None


class ReportConclusion(BaseModel):
    priorityActions: list[str]
    midTermActions: list[str]


class ProjectBundle(BaseModel):
    project: Project
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    attackChain: list[AttackChainNode] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    reportConclusion: Optional[ReportConclusion] = None


class ProjectSummary(BaseModel):
    id: str
    client: str
    codename: Optional[str] = None
    status: ProjectStatus
    engagementType: EngagementType
    updatedAt: str
    vulnerabilityCount: int = 0


class ProjectListResponse(BaseModel):
    projects: list[ProjectSummary]


class SyncResponse(BaseModel):
    ok: bool = True
    projectId: str
    updatedAt: str
