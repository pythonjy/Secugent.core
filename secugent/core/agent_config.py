# SPDX-License-Identifier: Apache-2.0
"""Agent configuration contracts for planner-guided work splitting."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from secugent.core.tenancy import TenantId

AgentKind = Literal["head", "sub"]


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class AgentNode(BaseModel):
    """A configured HEAD or SUB agent node shown in the agent config UI."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=80)
    kind: AgentKind
    actor: str = Field(..., min_length=1, max_length=120)
    name: str = Field(..., min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    role: str = Field(default="", max_length=200)
    harness: str = Field(default="Single-pass", max_length=120)
    model: str = Field(default="claude-sonnet-4-6", max_length=120)
    parent_id: str | None = Field(default=None, max_length=80)
    enabled: bool = True

    @field_validator("actor")
    @classmethod
    def _actor_prefix_matches_kind(cls, value: str, info: ValidationInfo) -> str:
        kind = info.data.get("kind")
        if kind == "sub" and not value.startswith("sub:"):
            raise ValueError("SUB agent actor must start with 'sub:'")
        if kind == "head" and value.startswith("sub:"):
            raise ValueError("HEAD agent actor cannot start with 'sub:'")
        return value


class AgentConfig(BaseModel):
    """Tenant-scoped current agent configuration."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    nodes: list[AgentNode] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validate_tree(self) -> AgentConfig:
        if not any(n.kind == "head" for n in self.nodes):
            raise ValueError("agent config must contain at least one HEAD")

        # SG-20260602-06: existence is not enough — a config where every node is
        # disabled (e.g. an operator/attacker flips all `enabled` to False) would
        # pass the existence check yet leave the planner with no routable HEAD or
        # SUB at /command enqueue time. Require at least one *enabled* HEAD and
        # one *enabled* SUB so a saved config is always executable (fail-closed
        # against an unusable topology).
        if not any(n.kind == "head" and n.enabled for n in self.nodes):
            raise ValueError("agent config must contain at least one enabled HEAD")
        if not any(n.kind == "sub" and n.enabled for n in self.nodes):
            raise ValueError("agent config must contain at least one enabled SUB")

        ids: set[str] = set()
        actors: set[str] = set()
        by_id: dict[str, AgentNode] = {}
        for node in self.nodes:
            if node.id in ids:
                raise ValueError(f"duplicate agent node id: {node.id}")
            if node.actor in actors:
                raise ValueError(f"duplicate agent actor: {node.actor}")
            ids.add(node.id)
            actors.add(node.actor)
            by_id[node.id] = node

        for node in self.nodes:
            if node.kind == "head" and node.parent_id is not None:
                raise ValueError("HEAD nodes must not have parent_id")
            if node.kind == "sub":
                if node.parent_id is None:
                    raise ValueError(f"SUB node {node.id} must have parent_id")
                if node.parent_id not in by_id:
                    raise ValueError(f"unknown parent_id for {node.id}: {node.parent_id}")

        for node in self.nodes:
            seen: set[str] = set()
            cursor = node
            while cursor.parent_id is not None:
                if cursor.id in seen:
                    raise ValueError(f"cycle detected at agent node {cursor.id}")
                seen.add(cursor.id)
                parent = by_id.get(cursor.parent_id)
                if parent is None:
                    break
                cursor = parent
            if cursor.id in seen:
                raise ValueError(f"cycle detected at agent node {cursor.id}")

        return self

    def enabled_sub_specs(self) -> list[dict[str, str]]:
        return [
            {
                "id": node.id,
                "actor": node.actor,
                "name": node.name,
                "role": node.role,
                "description": node.description,
                "harness": node.harness,
                "model": node.model,
                "parent_id": node.parent_id or "",
            }
            for node in self.nodes
            if node.kind == "sub" and node.enabled
        ]

    def enabled_head_specs(self) -> list[dict[str, str]]:
        return [
            {
                "id": node.id,
                "actor": node.actor,
                "name": node.name,
                "role": node.role,
                "description": node.description,
                "harness": node.harness,
                "model": node.model,
            }
            for node in self.nodes
            if node.kind == "head" and node.enabled
        ]


def default_agent_config(tenant_id: TenantId | str) -> AgentConfig:
    """Return the legacy visible agents as a valid editable tree."""

    return AgentConfig(
        tenant_id=TenantId(str(tenant_id)),
        nodes=[
            AgentNode(
                id="head",
                kind="head",
                actor="head",
                name="HEAD",
                description="전체 작업을 계획하고 하위 에이전트에 배정합니다.",
                role="오케스트레이션",
                harness="Plan-and-Execute",
                model="claude-opus-4-8",
            ),
            AgentNode(
                id="sub-researcher",
                kind="sub",
                actor="sub:researcher",
                name="Researcher",
                description="자료 수집과 보안 분석을 담당합니다.",
                role="보안 분석",
                parent_id="head",
            ),
            AgentNode(
                id="sub-writer",
                kind="sub",
                actor="sub:writer",
                name="Writer",
                description="보고서와 사용자-facing 결과물을 작성합니다.",
                role="리포트 작성",
                parent_id="head",
            ),
            AgentNode(
                id="sub-auditor",
                kind="sub",
                actor="sub:auditor",
                name="Auditor",
                description="규정 준수와 승인 위험을 점검합니다.",
                role="규제 준수 검토",
                parent_id="head",
            ),
        ],
    )
