# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""eurycleia - a task-scoped data vault for AI agents (working name).

Core:      Vault, Task, Policy, Blocked, AuditLog
Planner:   eurycleia.planner.Planner (provenance-tracked, CaMeL-style)
Storage:   eurycleia.crypto (customer-held keys), eurycleia.cache (read-through)
Adapters:  eurycleia.connectors, eurycleia.mcp (proxy), eurycleia.llm (models)
Tooling:   eurycleia.attacks (attack suite), `eurycleia` CLI
"""

__version__ = "0.6.0"

from .audit import AuditLog  # noqa: E402
from .policy import Policy, PolicyError  # noqa: E402
from .vault import ApprovalRequest, Blocked, SinkError, Task, Vault  # noqa: E402

__all__ = ["ApprovalRequest", "AuditLog", "Blocked", "Policy", "PolicyError", "SinkError", "Task", "Vault",
           "__version__"]
