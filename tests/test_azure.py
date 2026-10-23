# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Azure OpenAI, Azure sign-in and Key Vault keys, against stand-in Azure servers (no account, no network)."""

import base64
import json
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from eurycleia.azure import (
    KEY_VAULT_RESOURCE,
    OPENAI_RESOURCE,
    AzureSignInError,
    AzureToken,
    KeyVaultKey,
    key_vault_provider,
)
from eurycleia.crypto import Cipher, KeyUnavailable
from eurycleia.llm import PROVIDERS, AzureOpenAIProvider, make_provider
from eurycleia.webclient import ProviderError, check_url


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("IDENTITY_ENDPOINT", "IDENTITY_HEADER", "AZURE_ACCESS_TOKEN", "AZURE_CLIENT_ID",
                 "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_DEPLOYMENT", "EURYCLEIA_AZURE_VM"):
        monkeypatch.delenv(name, raising=False)


# ------------------------------------------------------------------ Azure OpenAI
def _reply(content="hi", calls=None):
    msg = {"role": "assistant", "content": content}
    if calls:
        msg["tool_calls"] = calls
    return {"choices": [{"message": msg}], "usage": {"prompt_tokens": 12, "completion_tokens": 3}}


def test_azure_openai_uses_the_v1_api_the_deployment_and_an_api_key():
    seen = []
    p = AzureOpenAIProvider("my-gpt", endpoint="https://res.openai.azure.com/", api_key="k123",
                            transport=lambda url, body, headers: seen.append((url, body, headers)) or _reply())
    assert p.complete("sys", "hello") == "hi"
    url, body, headers = seen[0]
    assert url == "https://res.openai.azure.com/openai/v1/chat/completions"
    assert body["model"] == "my-gpt" and headers == {"api-key": "k123"}
    assert p.usage["input"] == 12 and p.usage["output"] == 3


def test_azure_openai_without_a_key_signs_in_with_azure():
    seen = []
    p = AzureOpenAIProvider("dep", endpoint="https://res.services.ai.azure.com/openai/v1", api_key="",
                            transport=lambda u, b, h: seen.append((u, h)) or _reply(), token=lambda: "tok")
    p.complete("s", "u")
    assert seen == [("https://res.services.ai.azure.com/openai/v1/chat/completions", {"authorization": "Bearer tok"})]


def test_azure_openai_reads_its_settings_from_the_environment(monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://env.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "env-dep")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "envkey")
    seen = []
    p = AzureOpenAIProvider(transport=lambda u, b, h: seen.append((u, b["model"], h)) or _reply())
    p.complete("s", "u")
    assert seen == [("https://env.openai.azure.com/openai/v1/chat/completions", "env-dep", {"api-key": "envkey"})]


@pytest.mark.parametrize("endpoint", ["", "http://res.openai.azure.com", "res.openai.azure.com"])
def test_azure_openai_needs_an_https_endpoint(endpoint):
    with pytest.raises(ValueError, match="AZURE_OPENAI_ENDPOINT"):
        AzureOpenAIProvider("dep", endpoint=endpoint, api_key="k", transport=lambda u, b, h: _reply())


def test_azure_openai_runs_tools():
    replies = iter([_reply(None, [{"id": "c1", "type": "function",
                                   "function": {"name": "get_customer", "arguments": "{\"customer_id\": 12}"}}]),
                    _reply("done")])
    p = AzureOpenAIProvider("dep", endpoint="https://r.openai.azure.com", api_key="k",
                            transport=lambda u, b, h: next(replies))
    calls = []
    out = p.run_tools("s", "u", [{"name": "get_customer", "description": "d", "input_schema": {"type": "object"}}],
                      lambda name, args: calls.append((name, args)) or ("{}", False))
    assert out == "done" and calls == [("get_customer", {"customer_id": 12})]


def test_api_key_header_counts_as_a_secret_for_plain_http():
    with pytest.raises(ValueError, match="plain http"):
        check_url("http://example.com/x", sends_secret=True)


def test_make_provider_knows_every_name():
    assert "azure" in PROVIDERS
    p = make_provider("azure", "dep", endpoint="https://r.openai.azure.com", api_key="k",
                      transport=lambda u, b, h: _reply())
    assert isinstance(p, AzureOpenAIProvider)
    with pytest.raises(ValueError, match="unknown provider"):
        make_provider("nope")


# ------------------------------------------------------------------ sign-in
def test_managed_identity_token_is_fetched_and_reused_until_near_expiry(monkeypatch):
    monkeypatch.setenv("IDENTITY_ENDPOINT", "http://localhost:42356/msi/token")
    monkeypatch.setenv("IDENTITY_HEADER", "secret-header")
    now = [1_790_000_000.0]
    asked = []

    def get(url, headers):
        asked.append((url, headers))
        return {"access_token": f"t{len(asked)}", "expires_on": str(now[0] + 3600)}

    tok = AzureToken(OPENAI_RESOURCE, get=get, clock=lambda: now[0])
    assert tok() == "t1" and tok() == "t1"                      # reused
    url, headers = asked[0]
    q = parse_qs(urlsplit(url).query)
    assert url.startswith("http://localhost:42356/msi/token?") and q["resource"] == [OPENAI_RESOURCE]
    assert headers == {"x-identity-header": "secret-header"}
    now[0] += 3600 - 200                                        # within 5 minutes of expiry: renewed
    assert tok() == "t2"


def test_user_assigned_identity_is_asked_for_by_client_id(monkeypatch):
    monkeypatch.setenv("IDENTITY_ENDPOINT", "http://localhost:1/t")
    monkeypatch.setenv("IDENTITY_HEADER", "h")
    monkeypatch.setenv("AZURE_CLIENT_ID", "abc-123")
    asked = []
    AzureToken(KEY_VAULT_RESOURCE, get=lambda u, h: asked.append(u) or {"access_token": "x", "expires_in": 3600})()
    assert parse_qs(urlsplit(asked[0]).query)["client_id"] == ["abc-123"]


def test_virtual_machine_metadata_sign_in(monkeypatch):
    monkeypatch.setenv("EURYCLEIA_AZURE_VM", "1")
    asked = []
    tok = AzureToken(OPENAI_RESOURCE, get=lambda u, h: asked.append((u, h)) or {"access_token": "vm", "expires_in": 60})
    assert tok() == "vm"
    assert asked[0][0].startswith("http://169.254.169.254/") and asked[0][1] == {"metadata": "true"}


def test_azure_cli_sign_in_when_there_is_no_managed_identity():
    ran = []
    out = json.dumps({"accessToken": "cli-token", "expiresOn": "2026-10-19 15:00:00.000000"})
    tok = AzureToken(OPENAI_RESOURCE, run=lambda args: ran.append(args) or out)
    assert tok() == "cli-token"
    assert ran[0][:4] == ["account", "get-access-token", "--resource", OPENAI_RESOURCE]


def test_token_from_the_environment_as_a_last_resort(monkeypatch):
    monkeypatch.setenv("AZURE_ACCESS_TOKEN", "manual")
    assert AzureToken(OPENAI_RESOURCE, run=lambda a: "")() == "manual"


def test_clear_error_when_there_is_no_way_to_sign_in():
    def no_az(args):
        raise FileNotFoundError("az")
    with pytest.raises(AzureSignInError, match="az login"):
        AzureToken(OPENAI_RESOURCE, run=no_az)()


def test_refused_sign_in_is_reported_without_the_secret(monkeypatch):
    monkeypatch.setenv("IDENTITY_ENDPOINT", "http://localhost:1/t")
    monkeypatch.setenv("IDENTITY_HEADER", "super-secret")

    def refuse(url, headers):
        raise ProviderError(403, "forbidden")
    with pytest.raises(AzureSignInError) as e:
        AzureToken(OPENAI_RESOURCE, get=refuse)()
    assert "super-secret" not in str(e.value)


# ------------------------------------------------------------------ Key Vault
class FakeVault:
    """Key Vault's wrapkey/unwrapkey with a real RSA key and versions, and a switch to revoke access."""

    def __init__(self, host="my-vault.vault.azure.net"):
        self.host, self.revoked, self.calls = host, False, []
        self.versions = {"v1": rsa.generate_private_key(public_exponent=65537, key_size=2048)}
        self.current = "v1"

    def rotate(self):
        self.current = f"v{len(self.versions) + 1}"
        self.versions[self.current] = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def post(self, url, body, headers):
        self.calls.append((url, body["alg"], headers))
        if self.revoked:
            raise ProviderError(403, "Forbidden: the key is disabled")
        parts = urlsplit(url)
        assert parts.hostname == self.host and parse_qs(parts.query)["api-version"] == ["7.4"]
        assert body["alg"] == "RSA-OAEP-256" and headers["authorization"] == "Bearer kv-token"
        segs = parts.path.strip("/").split("/")                 # keys/<name>[/<version>]/<op>
        oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        value = base64.urlsafe_b64decode(body["value"] + "=" * (-len(body["value"]) % 4))
        if segs[-1] == "wrapkey":
            version = self.current
            out = self.versions[version].public_key().encrypt(value, oaep)
        else:
            version = segs[2]
            out = self.versions[version].decrypt(value, oaep)
        return {"kid": f"https://{self.host}/keys/{segs[1]}/{version}",
                "value": base64.urlsafe_b64encode(out).rstrip(b"=").decode()}


def _vault_key(vault):
    return KeyVaultKey(f"https://{vault.host}", "eurycleia-key", token=lambda: "kv-token", post=vault.post)


def test_key_vault_wraps_and_unwraps_the_data_key(tmp_path):
    vault = FakeVault()
    keys = key_vault_provider(f"https://{vault.host}", "eurycleia-key", tmp_path / "wrapped.key",
                              token=lambda: "kv-token", post=vault.post)
    data_key = keys.data_key()
    assert len(data_key) == 32 and data_key not in (tmp_path / "wrapped.key").read_bytes()
    blob = Cipher(keys).encrypt({"card": "4111111111111111"})
    fresh = key_vault_provider(f"https://{vault.host}", "eurycleia-key", tmp_path / "wrapped.key",
                               token=lambda: "kv-token", post=vault.post)
    assert Cipher(fresh).decrypt(blob) == {"card": "4111111111111111"}
    assert fresh.key_id == f"kms:azure-keyvault:{vault.host}/eurycleia-key"


def test_rotating_the_key_vault_key_keeps_old_data_readable(tmp_path):
    vault = FakeVault()
    keys = key_vault_provider(f"https://{vault.host}", "k", tmp_path / "w.key", token=lambda: "kv-token",
                              post=vault.post)
    before = keys.data_key()
    vault.rotate()
    again = key_vault_provider(f"https://{vault.host}", "k", tmp_path / "w.key", token=lambda: "kv-token",
                               post=vault.post)
    assert again.data_key() == before                          # unwrapped with the version that wrapped it


def test_revoking_the_key_makes_stored_data_unreadable(tmp_path):
    vault = FakeVault()
    path = tmp_path / "w.key"
    key_vault_provider(f"https://{vault.host}", "k", path, token=lambda: "kv-token", post=vault.post).data_key()
    vault.revoked = True
    with pytest.raises(KeyUnavailable, match="unwrap"):
        key_vault_provider(f"https://{vault.host}", "k", path, token=lambda: "kv-token", post=vault.post).data_key()


def test_a_tampered_wrapped_key_cannot_send_the_token_to_another_server(tmp_path):
    vault = FakeVault()
    key = _vault_key(vault)
    wrapped = json.loads(key.encrypt(b"x" * 32))
    wrapped["kid"] = "https://attacker.example/keys/k/v1"
    with pytest.raises(ValueError, match="different vault"):
        key.decrypt(json.dumps(wrapped).encode())
    assert all(urlsplit(u).hostname == vault.host for u, _a, _h in vault.calls)


@pytest.mark.parametrize("url", ["http://my-vault.vault.azure.net", "my-vault.vault.azure.net", ""])
def test_key_vault_address_must_be_https(url):
    with pytest.raises(ValueError, match="https"):
        KeyVaultKey(url, "k", token=lambda: "t", post=lambda u, b, h: {})


def test_key_vault_secret_is_read_with_the_apps_identity():
    from eurycleia.azure import key_vault_secret
    asked = []
    value = key_vault_secret("https://my-vault.vault.azure.net", "gmail-app-password", token=lambda: "kv",
                             get=lambda u, h: asked.append((u, h)) or {"value": "abcd efgh"})
    assert value == "abcd efgh"
    assert asked == [("https://my-vault.vault.azure.net/secrets/gmail-app-password?api-version=7.4",
                      {"authorization": "Bearer kv"})]


def test_key_vault_secret_errors_never_include_the_token():
    from eurycleia.azure import key_vault_secret

    def refuse(u, h):
        raise ProviderError(403, "Forbidden")
    with pytest.raises(AzureSignInError, match="gmail") as e:
        key_vault_secret("https://v.vault.azure.net", "gmail", token=lambda: "secret-token", get=refuse)
    assert "secret-token" not in str(e.value)


def test_a_missing_key_vault_secret_is_told_apart_from_a_refusal():
    from eurycleia.azure import SecretNotFound, key_vault_secret

    def missing(u, h):
        raise ProviderError(404, "A secret with (name/id) gmail-app-password was not found")
    with pytest.raises(SecretNotFound):
        key_vault_secret("https://v.vault.azure.net", "gmail-app-password", token=lambda: "kv", get=missing)
