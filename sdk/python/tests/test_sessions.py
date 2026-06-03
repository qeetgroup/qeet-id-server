"""Mirrors sdk/go/sessions_test.go: generate an ES256 key, sign a JWT, build a
JWKS dict from the public key, and verify the token through Sessions.verify.
"""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from qeetid.errors import SessionVerificationError
from qeetid.sessions import Sessions, VerifyOptions


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_json(obj) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _jwk_from_public(pub: ec.EllipticCurvePublicKey, kid: str) -> dict:
    nums = pub.public_numbers()
    size = 32  # P-256 coordinate size
    return {
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "use": "sig",
        "x": _b64url(nums.x.to_bytes(size, "big")),
        "y": _b64url(nums.y.to_bytes(size, "big")),
    }


def _mint(priv: ec.EllipticCurvePrivateKey, payload: dict, kid: str = "test-kid") -> str:
    signing_input = (
        _b64url_json({"alg": "ES256", "typ": "JWT", "kid": kid})
        + "."
        + _b64url_json(payload)
    )
    der = priv.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input + "." + _b64url(raw_sig)


def _sessions_with_jwks(jwks: dict) -> Sessions:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/jwks.json"
        return httpx.Response(200, json=jwks)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return Sessions("https://id.test", client)


@pytest.fixture
def keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def test_verify_valid_token(keypair):
    priv, pub = keypair
    jwks = {"keys": [_jwk_from_public(pub, "test-kid")]}
    sessions = _sessions_with_jwks(jwks)
    now = int(time.time())

    tok = _mint(
        priv,
        {
            "sub": "usr_1",
            "user_id": "usr_1",
            "tenant_id": "tnt_1",
            "sid": "sess_1",
            "iss": "https://id.test",
            "aud": "rp",
            "exp": now + 3600,
            "iat": now,
        },
    )

    claims = sessions.verify(tok)
    assert claims.user_id == "usr_1"
    assert claims.tenant_id == "tnt_1"
    assert claims.session_id == "sess_1"
    assert claims.subject == "usr_1"
    assert claims.issuer == "https://id.test"
    assert claims.expires_at == now + 3600
    assert claims.audience == "rp"
    assert claims.raw["user_id"] == "usr_1"


def test_issuer_and_audience_enforced(keypair):
    priv, pub = keypair
    sessions = _sessions_with_jwks({"keys": [_jwk_from_public(pub, "test-kid")]})
    now = int(time.time())
    tok = _mint(
        priv,
        {"sub": "u", "iss": "https://id.test", "aud": "rp", "exp": now + 3600, "iat": now},
    )

    # Matching iss/aud should pass.
    claims = sessions.verify(
        tok, VerifyOptions(issuer="https://id.test", audience="rp")
    )
    assert claims.subject == "u"

    # Wrong issuer must reject.
    with pytest.raises(SessionVerificationError):
        sessions.verify(tok, VerifyOptions(issuer="https://evil"))

    # Wrong audience must reject.
    with pytest.raises(SessionVerificationError):
        sessions.verify(tok, VerifyOptions(audience="other"))


def test_expired_token_rejected(keypair):
    priv, pub = keypair
    sessions = _sessions_with_jwks({"keys": [_jwk_from_public(pub, "test-kid")]})
    now = int(time.time())
    tok = _mint(priv, {"sub": "u", "exp": now - 3600, "iat": now - 7200})
    with pytest.raises(SessionVerificationError):
        sessions.verify(tok)


def test_tampered_signature_rejected(keypair):
    priv, pub = keypair
    sessions = _sessions_with_jwks({"keys": [_jwk_from_public(pub, "test-kid")]})
    now = int(time.time())
    tok = _mint(priv, {"sub": "u", "exp": now + 3600, "iat": now})
    bad = tok[:-3] + ("AAA" if tok[-3:] != "AAA" else "BBB")
    with pytest.raises(SessionVerificationError):
        sessions.verify(bad)


def test_token_signed_by_different_key_rejected(keypair):
    priv, pub = keypair
    sessions = _sessions_with_jwks({"keys": [_jwk_from_public(pub, "test-kid")]})
    now = int(time.time())
    other = ec.generate_private_key(ec.SECP256R1())
    tok = _mint(other, {"sub": "u", "exp": now + 100})
    with pytest.raises(SessionVerificationError):
        sessions.verify(tok)


def test_unknown_kid_rejected(keypair):
    priv, pub = keypair
    sessions = _sessions_with_jwks({"keys": [_jwk_from_public(pub, "test-kid")]})
    now = int(time.time())
    tok = _mint(priv, {"sub": "u", "exp": now + 100}, kid="other-kid")
    with pytest.raises(SessionVerificationError):
        sessions.verify(tok)


def test_malformed_token_rejected(keypair):
    priv, pub = keypair
    sessions = _sessions_with_jwks({"keys": [_jwk_from_public(pub, "test-kid")]})
    with pytest.raises(SessionVerificationError):
        sessions.verify("not.a.jwt.token")
    with pytest.raises(SessionVerificationError):
        sessions.verify("onlyonepart")


def test_unsupported_alg_rejected(keypair):
    priv, pub = keypair
    sessions = _sessions_with_jwks({"keys": [_jwk_from_public(pub, "test-kid")]})
    now = int(time.time())
    header = _b64url_json({"alg": "HS256", "typ": "JWT", "kid": "test-kid"})
    payload = _b64url_json({"sub": "u", "exp": now + 100})
    tok = header + "." + payload + "." + _b64url(b"x" * 64)
    with pytest.raises(SessionVerificationError) as exc:
        sessions.verify(tok)
    assert "unsupported alg" in str(exc.value)
