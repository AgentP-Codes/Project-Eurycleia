# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Exception hierarchy. Catch `TaskvaultError` to handle anything taskvault raises on purpose."""


class TaskvaultError(Exception):
    """Base class for taskvault errors."""
