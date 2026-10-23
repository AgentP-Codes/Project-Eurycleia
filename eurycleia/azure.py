# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Azure, with no Azure SDK: sign-in tokens and Key Vault keys over Azure's REST APIs.

Sign-in (no password or key stored anywhere), tried in this order:

  1. the app's own Azure identity ("managed identity"): on Azure Container Apps and App Service through
     IDENTITY_ENDPOINT / IDENTITY_HEADER, on an Azure virtual machine through its metadata address;
  2. the Azure CLI on your own computer (`az login` first), for trying things out;
  3. AZURE_ACCESS_TOKEN, a token you got some other way (it expires after about an hour).

Key Vault holds eurycleia's data key the same way AWS KMS does (see crypto.KMSKeyProvider): the data key is
stored only wrapped by a Key Vault key, and unwrapped in memory. Revoking the key in Key Vault makes everything
stored under it unreadable.

    from eurycleia.azure import key_vault_provider
    keys = key_vault_provider("https://my-vault.vault.azure.net", "eurycleia-key", "wrapped-data.key")
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from .errors import EurycleiaError
from .webclient import ProviderError, get_json, post_json

OPENAI_RESOURCE = "https://cognitiveservices.azure.com"
KEY_VAULT_RESOURCE = "https://vault.azure.net"
KEY_VAULT_API = "7.4"
IMDS = "http://169.254.169.254/metadata/identity/oauth2/token"

Get = Callable[[str, dict[str, str]], dict[str, Any]]                  # (url, headers) -> JSON
Post = Callable[[str, dict[str, Any], dict[str, str]], dict[str, Any]]  # (url, body, headers) -> JSON


class AzureSignInError(EurycleiaError):
    """No way to sign in to Azure was found, or Azure refused."""


class AzureToken:
    """Bearer tokens for one Azure resource, renewed five minutes before they expire. Thread-safe."""

    def __init__(self, resource: str, client_id: str | None = None, get: Get | None = None,
                 run: Callable[[list[str]], str] | None = None, clock: Callable[[], float] = time.time):
        self.resource, self.clock = resource.rstrip("/"), clock
        self.client_id = client_id or os.environ.get("AZURE_CLIENT_ID") or None   # a user-assigned identity
        self._get = get or (lambda url, headers: get_json(url, headers, timeout=15))
        self._run = run or _run_az
        self._token, self._expires = "", 0.0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            if not self._token or self.clock() > self._expires - 300:
                self._token, self._expires = self._fetch()
            return self._token

    def _fetch(self) -> tuple[str, float]:
        endpoint, secret = os.environ.get("IDENTITY_ENDPOINT"), os.environ.get("IDENTITY_HEADER")
        if endpoint and secret:                                  # Container Apps, App Service
            q = {"resource": self.resource, "api-version": "2019-08-01"}
            if self.client_id:
                q["client_id"] = self.client_id
            return self._parse(self._ask(f"{endpoint}?{urlencode(q)}", {"x-identity-header": secret}))
        if os.environ.get("EURYCLEIA_AZURE_VM"):                 # a virtual machine's metadata address
            q = {"resource": self.resource, "api-version": "2018-02-01"}
            if self.client_id:
                q["client_id"] = self.client_id
            return self._parse(self._ask(f"{IMDS}?{urlencode(q)}", {"metadata": "true"}))
        try:
            out = self._run(["account", "get-access-token", "--resource", self.resource, "--output", "json"])
        except FileNotFoundError:
            out = ""
        if out:
            return self._parse(json.loads(out))
        token = os.environ.get("AZURE_ACCESS_TOKEN")
        if token:
            return token, self.clock() + 1800
        raise AzureSignInError(
            "couldn't sign in to Azure: no managed identity here, the Azure CLI isn't signed in (`az login`), "
            "and AZURE_ACCESS_TOKEN isn't set")

    def _ask(self, url: str, headers: dict[str, str]) -> dict[str, Any]:
        try:
            return self._get(url, headers)
        except ProviderError as e:
            raise AzureSignInError(f"Azure sign-in refused: {e}") from None

    def _parse(self, reply: dict[str, Any]) -> tuple[str, float]:
        token = reply.get("access_token") or reply.get("accessToken")
        if not token:
            raise AzureSignInError("Azure sign-in sent no token")
        expires = reply.get("expires_on") or reply.get("expiresOn") or reply.get("expires_in")
        try:
            at = float(expires)
            at = at if at > 10**9 else self.clock() + at            # a timestamp, or seconds from now
        except (TypeError, ValueError):
            at = self.clock() + 1800                                # e.g. the CLI's "2026-10-19 14:00:00"
        return str(token), at


def _run_az(args: list[str]) -> str:
    az = shutil.which("az")
    if not az:
        raise FileNotFoundError("az")
    done = subprocess.run([az, *args], capture_output=True, text=True, timeout=60)
    return done.stdout if done.returncode == 0 else ""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class KeyVaultKey:
    """Wraps and unwraps eurycleia's data key with an RSA key in Azure Key Vault (RSA-OAEP-256).

    Fits crypto.KMSKeyProvider: `encrypt` wraps, `decrypt` unwraps. The wrapped form records the exact key
    version used, so the data key still opens after the Key Vault key is rotated (until the old version is
    disabled or deleted, which is how you revoke it)."""

    def __init__(self, vault_url: str, key_name: str, token: Callable[[], str] | None = None,
                 post: Post | None = None):
        parts = urlsplit(vault_url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("vault_url must be the vault's https address, e.g. https://my-vault.vault.azure.net")
        self.vault = f"https://{parts.hostname}"
        self.key_name = key_name
        self.token = token or AzureToken(KEY_VAULT_RESOURCE)
        self._post = post or (lambda url, body, headers: post_json(url, body, headers, timeout=30))

    def _call(self, url: str, value: bytes) -> dict[str, Any]:
        if urlsplit(url).hostname != urlsplit(self.vault).hostname:
            raise ValueError("refusing to send a key to a different vault")
        return self._post(f"{url}?api-version={KEY_VAULT_API}", {"alg": "RSA-OAEP-256", "value": _b64url(value)},
                          {"authorization": f"Bearer {self.token()}"})

    def encrypt(self, plaintext: bytes) -> bytes:
        r = self._call(f"{self.vault}/keys/{quote(self.key_name, safe='')}/wrapkey", plaintext)
        return json.dumps({"kid": r["kid"], "value": r["value"]}).encode()

    def decrypt(self, ciphertext: bytes) -> bytes:
        wrapped = json.loads(ciphertext)
        return _unb64url(self._call(f"{wrapped['kid']}/unwrapkey", _unb64url(wrapped["value"]))["value"])


def key_vault_provider(vault_url: str, key_name: str, wrapped_key_path: str | Path, **kw: Any):
    """A crypto.KMSKeyProvider whose data key is wrapped by `key_name` in the given Key Vault."""
    from .crypto import KMSKeyProvider
    return KMSKeyProvider(KeyVaultKey(vault_url, key_name, **kw), wrapped_key_path,
                          key_id=f"azure-keyvault:{urlsplit(vault_url).hostname}/{key_name}")


class SecretNotFound(AzureSignInError):
    """Key Vault answered, but has no secret by that name (it may be optional)."""


def key_vault_secret(vault_url: str, name: str, token: Callable[[], str] | None = None,
                     get: Get | None = None) -> str:
    """Read one secret (an app password, an API token) from Key Vault, signed in as the app's own identity.
    The value is returned to the caller only: eurycleia never logs or stores it."""
    parts = urlsplit(vault_url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("vault_url must be the vault's https address, e.g. https://my-vault.vault.azure.net")
    token = token or AzureToken(KEY_VAULT_RESOURCE)
    get = get or (lambda url, headers: get_json(url, headers, timeout=30))
    try:
        reply = get(f"https://{parts.hostname}/secrets/{quote(name, safe='')}?api-version={KEY_VAULT_API}",
                    {"authorization": f"Bearer {token()}"})
    except ProviderError as e:
        if e.status == 404:
            raise SecretNotFound(f"Key Vault has no secret {name!r}") from None
        raise AzureSignInError(f"Key Vault wouldn't give secret {name!r}: {e}") from None
    value = reply.get("value")
    if not isinstance(value, str):
        raise AzureSignInError(f"Key Vault secret {name!r} has no value")
    return value
