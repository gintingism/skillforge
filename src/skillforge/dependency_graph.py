"""Skill dependency graph analyzer, topological resolver, and privilege escalation detector."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from skillforge.security import Severity
from skillforge.skill import SkillPackage

_HIGH_RISK_TOOLS = {"bash", "shell", "terminal", "write", "edit", "delete", "exec", "ssh", "curl"}


@dataclass(frozen=True, slots=True)
class GraphIssue:
    """An issue discovered during skill dependency graph analysis."""

    rule_id: str
    severity: Severity
    skill_name: str
    message: str


@dataclass(frozen=True, slots=True)
class GraphNode:
    """A node in the resolved skill dependency graph."""

    name: str
    dependencies: tuple[str, ...]
    direct_tokens: int
    transitive_tokens: int
    allowed_tools: tuple[str, ...]


@dataclass
class DependencyGraphReport:
    """Consolidated report from skill dependency graph resolution."""

    nodes: list[GraphNode] = field(default_factory=list)
    topological_order: list[str] = field(default_factory=list)
    issues: list[GraphIssue] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True if no CRITICAL or HIGH severity graph issues exist."""
        return not any(i.severity in (Severity.CRITICAL, Severity.HIGH) for i in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "node_count": len(self.nodes),
            "topological_order": self.topological_order,
            "issues_count": len(self.issues),
            "nodes": [
                {
                    "name": n.name,
                    "dependencies": list(n.dependencies),
                    "direct_tokens": n.direct_tokens,
                    "transitive_tokens": n.transitive_tokens,
                    "allowed_tools": list(n.allowed_tools),
                }
                for n in self.nodes
            ],
            "issues": [
                {
                    "rule_id": i.rule_id,
                    "severity": i.severity.value,
                    "skill_name": i.skill_name,
                    "message": i.message,
                }
                for i in self.issues
            ],
        }

    def to_mermaid(self) -> str:
        """Render the skill dependency graph as a Mermaid flowchart TD diagram."""
        lines = ["flowchart TD"]
        if not self.nodes:
            lines.append('    empty["No skills discovered"]')
            return "\n".join(lines)

        for node in self.nodes:
            safe_id = node.name.replace("-", "_")
            label = f'{node.name} ({node.transitive_tokens} tok)'
            lines.append(f'    {safe_id}["{label}"]')
            for dep in node.dependencies:
                dep_id = dep.replace("-", "_")
                lines.append(f"    {safe_id} --> {dep_id}")
        return "\n".join(lines)

    def render_text(self) -> str:
        status = "PASSED" if self.passed else "FAILED"
        lines = [
            f"Skill Dependency Graph Analysis: {status}",
            f"  Skills Analyzed:   {len(self.nodes)}",
            f"  Topological Order: {' -> '.join(self.topological_order) if self.topological_order else 'N/A (cycle detected or empty)'}",
            f"  Issues Detected:   {len(self.issues)}",
        ]
        if self.nodes:
            lines.append("\nNodes:")
            for n in self.nodes:
                deps_str = ", ".join(n.dependencies) if n.dependencies else "none"
                lines.append(
                    f"  * {n.name}: deps=[{deps_str}] "
                    f"direct={n.direct_tokens} tok, transitive={n.transitive_tokens} tok"
                )
        if self.issues:
            lines.append("\nIssues:")
            for issue in self.issues:
                lines.append(f"  [{issue.severity.value}] {issue.rule_id} ({issue.skill_name}): {issue.message}")
        return "\n".join(lines)


def _parse_tools(allowed_tools_str: str | None) -> tuple[str, ...]:
    if not allowed_tools_str:
        return ()
    parts = [p.strip() for p in allowed_tools_str.replace(",", " ").split() if p.strip()]
    return tuple(dict.fromkeys(parts))


def analyze_dependency_graph(packages: dict[str, SkillPackage]) -> DependencyGraphReport:
    """Analyze skill dependency relationships, detect cycles, and compute topological load order."""
    issues: list[GraphIssue] = []
    adj: dict[str, tuple[str, ...]] = {}
    tools_map: dict[str, tuple[str, ...]] = {}

    for name, pkg in sorted(packages.items()):
        deps = pkg.skill.dependencies
        adj[name] = deps
        tools_map[name] = _parse_tools(pkg.skill.allowed_tools)

        # DEP-002: Missing dependency check
        for dep in deps:
            if dep not in packages:
                issues.append(
                    GraphIssue(
                        rule_id="DEP-002",
                        severity=Severity.HIGH,
                        skill_name=name,
                        message=f"Skill '{name}' declares missing dependency '{dep}' which is not installed.",
                    )
                )

    # DEP-001: Cycle detection via 3-color DFS (0=unvisited, 1=visiting, 2=visited)
    state: dict[str, int] = {name: 0 for name in packages}
    topo_order: list[str] = []
    has_cycle = False

    def _dfs(current: str, stack: list[str]) -> None:
        nonlocal has_cycle
        state[current] = 1
        stack.append(current)
        for dep in adj.get(current, ()):
            if dep not in state:
                continue
            if state[dep] == 1:
                has_cycle = True
                cycle_start = stack.index(dep)
                cycle_path = " -> ".join(stack[cycle_start:] + [dep])
                issues.append(
                    GraphIssue(
                        rule_id="DEP-001",
                        severity=Severity.CRITICAL,
                        skill_name=current,
                        message=f"Circular skill dependency detected: {cycle_path}",
                    )
                )
            elif state[dep] == 0:
                _dfs(dep, stack)
        stack.pop()
        state[current] = 2
        topo_order.append(current)

    for name in sorted(packages):
        if state[name] == 0:
            _dfs(name, [])

    if has_cycle:
        topo_order = []

    # DEP-003: Privilege escalation across dependency edges
    for name, deps in sorted(adj.items()):
        parent_tools_lower = {t.lower().split("(")[0] for t in tools_map[name]}
        if not parent_tools_lower:
            continue
        for dep in deps:
            if dep not in packages:
                continue
            dep_tools_lower = {t.lower().split("(")[0] for t in tools_map[dep]}
            escalated = sorted((dep_tools_lower & _HIGH_RISK_TOOLS) - parent_tools_lower)
            if escalated:
                issues.append(
                    GraphIssue(
                        rule_id="DEP-003",
                        severity=Severity.MEDIUM,
                        skill_name=name,
                        message=(
                            f"Dependency '{dep}' requests high-risk allowed-tools "
                            f"({', '.join(escalated)}) not declared by parent skill '{name}'."
                        ),
                    )
                )

    # Compute transitive token cost per node (memoized with cycle guard)
    def _transitive_tokens(start: str) -> int:
        visited: set[str] = set()
        stack = [start]
        total = 0
        while stack:
            curr = stack.pop()
            if curr in visited or curr not in packages:
                continue
            visited.add(curr)
            total += packages[curr].total_tokens
            for dep in adj.get(curr, ()):
                if dep not in visited:
                    stack.append(dep)
        return total

    nodes: list[GraphNode] = []
    for name, pkg in sorted(packages.items()):
        nodes.append(
            GraphNode(
                name=name,
                dependencies=adj[name],
                direct_tokens=pkg.total_tokens,
                transitive_tokens=_transitive_tokens(name),
                allowed_tools=tools_map[name],
            )
        )

    return DependencyGraphReport(
        nodes=nodes,
        topological_order=topo_order,
        issues=issues,
    )
