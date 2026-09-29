# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared test fixtures."""

import itertools

import pytest

_db_ids = itertools.count(1)


@pytest.fixture(scope="session")
def _pg_server(tmp_path_factory):
    """One embedded Postgres for the whole test run (starting one per test was most of the suite's time)."""
    pgserver = pytest.importorskip("pgserver")
    pytest.importorskip("psycopg")
    return pgserver.get_server(str(tmp_path_factory.mktemp("pg")), cleanup_mode="stop")


@pytest.fixture
def pg_url(_pg_server):
    """A fresh, empty Postgres database for one test."""
    name = f"t{next(_db_ids)}"
    _pg_server.psql(f"CREATE DATABASE {name};")
    return _pg_server.get_uri(database=name)
