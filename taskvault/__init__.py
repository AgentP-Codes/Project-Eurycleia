# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""taskvault is now Eurycleia (`import eurycleia`). This keeps code written for taskvault 0.5 working:
`taskvault.<module>` is the very same module as `eurycleia.<module>`, so classes and errors are shared."""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import sys

from eurycleia import *  # noqa: F403
from eurycleia import __all__, __version__  # noqa: F401


class _Alias(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, name, path=None, target=None):
        if name.startswith("taskvault.") and name != "taskvault.__main__":
            return importlib.util.spec_from_loader(name, self)
        return None

    def create_module(self, spec):
        return importlib.import_module("eurycleia" + spec.name[len("taskvault"):])

    def exec_module(self, module):
        pass                                        # already loaded as eurycleia.<module>


if not any(isinstance(f, _Alias) for f in sys.meta_path):
    sys.meta_path.insert(0, _Alias())
