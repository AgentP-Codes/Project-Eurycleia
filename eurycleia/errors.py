# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Exception hierarchy. Catch `EurycleiaError` to handle anything eurycleia raises on purpose."""


class EurycleiaError(Exception):
    """Base class for eurycleia errors."""


TaskvaultError = EurycleiaError     # the name before 0.6, kept so existing code still works
