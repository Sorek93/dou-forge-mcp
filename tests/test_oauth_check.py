"""Offline protocol-shape tests; no external identity account or token is used."""

import copy
import pytest
from douforge.config import Config, ForgeError
from douforge.oauth_check import check_oauth, discovery_urls, get_json

ISSUER = "https://id.example.com/realms/forge"
RESOURCE = "https://forge.example.com/mcp"
JWKS = ISSUER + "/jwks"


def fixture():
    cfg = Config(
        {
            "version": 1,
            "http": {"auth_mode": "jwt", "issuer_url": ISSUER, "resource_url": RESOURCE, "jwks_url": JWKS},
        }
    )
    prm = {"resource": RESOURCE, "authorization_servers": [ISSUER], "scopes_supported": ["forge:use"]}
    meta = {
        "issuer": ISSUER,
        "code_challenge_methods_supported": ["S256"],
        "response_types_supported": ["code"],
        "authorization_endpoint": ISSUER + "/authorize",
        "token_endpoint": ISSUER + "/token",
        "jwks_uri": JWKS,
    }
    docs = {
        "https://forge.example.com/.well-known/oauth-protected-resource/mcp": prm,
        discovery_urls(ISSUER)[0]: meta,
        JWKS: {"keys": [{"kty": "RSA", "n": "synthetic", "e": "AQAB"}]},
    }

    def fetch(url):
        if url not in docs:
            raise ForgeError("fixture missing")
        return copy.deepcopy(docs[url])

    return cfg, docs, fetch, meta, prm


def test_readiness_never_claims_login():
    cfg, _, fetch, _, _ = fixture()
    report = check_oauth(cfg, fetch=fetch)
    assert report["status"] == "metadata_ready"
    assert report["login_verified"] is report["chatgpt_verified"] is False


def test_preview_does_not_fetch():
    cfg = Config(
        {
            "version": 1,
            "principals": {"local": {}},
            "http": {
                "auth_mode": "preview",
                "issuer_url": "http://127.0.0.1",
                "resource_url": "http://127.0.0.1/mcp",
                "preview_principal": "local",
            },
        }
    )
    assert check_oauth(cfg, fetch=lambda _: pytest.fail("preview must not fetch"))["status"] == "blocked"


def test_oidc_fallback_preserves_issuer_path():
    cfg, docs, fetch, meta, _ = fixture()
    docs.pop(discovery_urls(ISSUER)[0])
    docs[discovery_urls(ISSUER)[1]] = meta
    assert check_oauth(cfg, fetch=fetch)["status"] == "metadata_ready"


def test_root_resource_fallback():
    cfg, docs, fetch, _, prm = fixture()
    docs.pop("https://forge.example.com/.well-known/oauth-protected-resource/mcp")
    docs["https://forge.example.com/.well-known/oauth-protected-resource"] = prm
    assert check_oauth(cfg, fetch=fetch)["status"] == "metadata_ready"


@pytest.mark.parametrize(
    "field,value",
    [
        ("issuer", ISSUER + "/"),
        ("code_challenge_methods_supported", ["plain"]),
        ("response_types_supported", ["token"]),
        ("authorization_endpoint", "http://bad.example.com"),
        ("token_endpoint", "https://user@example.com"),
        ("jwks_uri", "https://another.example.com/jwks"),
        ("code_challenge_methods_supported", "S256"),
    ],
)
def test_bad_issuer_metadata(field, value):
    cfg, _, fetch, meta, _ = fixture()
    meta[field] = value
    assert check_oauth(cfg, fetch=fetch)["status"] == "blocked"


@pytest.mark.parametrize(
    "field,value",
    [
        ("resource", RESOURCE + "/"),
        ("authorization_servers", []),
        ("authorization_servers", ISSUER),
        ("scopes_supported", []),
        ("scopes_supported", "forge:use"),
        ("scopes_supported", [42]),
    ],
)
def test_bad_protected_resource_metadata(field, value):
    cfg, _, fetch, _, prm = fixture()
    prm[field] = value
    assert check_oauth(cfg, fetch=fetch)["status"] == "blocked"


def test_unavailable_provider_does_not_print_details():
    cfg, _, _, _, _ = fixture()

    def fail(_):
        raise ForgeError("SECRET_PROVIDER_BODY")

    report = check_oauth(cfg, fetch=fail)
    assert report["status"] == "blocked" and "SECRET_PROVIDER_BODY" not in str(report)


def test_cimd_and_dcr_are_explicit():
    cfg, _, fetch, meta, _ = fixture()
    assert check_oauth(cfg, registration="cimd", fetch=fetch)["status"] == "blocked"
    meta["client_id_metadata_document_supported"] = True
    assert check_oauth(cfg, registration="cimd", fetch=fetch)["status"] == "metadata_ready"
    assert check_oauth(cfg, registration="dcr", fetch=fetch)["status"] == "blocked"
    meta["registration_endpoint"] = ISSUER + "/register"
    assert check_oauth(cfg, registration="dcr", fetch=fetch)["status"] == "metadata_ready"


@pytest.mark.parametrize(
    "key",
    [
        {"kty": "oct", "k": "never-use-shared-secret"},
        {"kty": "RSA", "n": "n"},
        {"kty": "RSA", "n": "n", "e": "e", "use": "enc"},
    ],
)
def test_unsupported_jwks(key):
    cfg, docs, fetch, _, _ = fixture()
    docs[JWKS] = {"keys": [key]}
    assert check_oauth(cfg, fetch=fetch)["status"] == "blocked"


def test_get_json_rejects_http_before_network():
    with pytest.raises(ForgeError):
        get_json("http://example.com")


def test_no_requests_to_authorization_or_token_endpoints():
    cfg, _, fetch, _, _ = fixture()
    requested = []

    def observed(url):
        requested.append(url)
        return fetch(url)

    check_oauth(cfg, fetch=observed)
    assert requested == [
        "https://forge.example.com/.well-known/oauth-protected-resource/mcp",
        discovery_urls(ISSUER)[0],
        JWKS,
    ]


def test_loopback_http_resource_not_remote_ready():
    cfg, _, fetch, _, _ = fixture()
    raw = cfg.raw.copy()
    raw["http"] = {**raw["http"], "resource_url": "http://127.0.0.1/mcp"}
    assert check_oauth(Config(raw), fetch=fetch)["status"] == "blocked"



def test_scopes_supported_absent_is_valid_with_actionable_warning():
    cfg, _, fetch, _, prm = fixture()
    prm.pop("scopes_supported")
    report = check_oauth(cfg, fetch=fetch)
    assert report["status"] == "metadata_ready"
    assert report["warnings"][0]["check"] == "scope_advertised"
    assert report["login_verified"] is report["chatgpt_verified"] is False


def test_scopes_supported_nonexhaustive_is_warning_not_denial():
    cfg, _, fetch, _, prm = fixture()
    prm["scopes_supported"] = ["other:read"]
    report = check_oauth(cfg, fetch=fetch)
    assert report["status"] == "metadata_ready"
    assert "401" in report["warnings"][0]["message"]


def test_scopes_supported_empty_is_rejected_per_rfc9728():
    cfg, _, fetch, _, prm = fixture()
    prm["scopes_supported"] = []
    report = check_oauth(cfg, fetch=fetch)
    assert report["status"] == "blocked"


def test_scope_verifier_still_requires_forge_use():
    cfg, _, fetch, _, _ = fixture()
    assert check_oauth(cfg, fetch=fetch)["login_verified"] is False
