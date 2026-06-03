"""Session/JWT verification against the issuer's published JWKS.

Verifies Qeet-issued **ES256** (ECDSA P-256) tokens against the keys published
at ``<base_url>/.well-known/jwks.json``. After the keys are cached it is fully
local, so it's cheap to call on every request. Mirrors ``sdk/go/sessions.go``
(IEEE-P1363 raw-``r||s`` ECDSA verification) and the TS ``Sessions`` class.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .errors import SessionVerificationError

__all__ = ["Sessions", "SessionClaims", "VerifyOptions"]

JWKS_TTL_SECONDS = 5 * 60


@dataclass
class SessionClaims:
    """The verified content of a Qeet-issued token."""

    user_id: str
    subject: str
    expires_at: int
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None
    scope: Optional[str] = None
    issuer: Optional[str] = None
    audience: Optional[Union[str, List[str]]] = None
    issued_at: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerifyOptions:
    """Tightens verification. ``clock_tolerance_seconds`` defaults to 30."""

    issuer: Optional[str] = None
    audience: Optional[str] = None
    clock_tolerance_seconds: int = 30


class Sessions:
    """Verifies ES256 tokens against the issuer's published JWKS.

    The JWKS is fetched lazily on first use, cached for
    :data:`JWKS_TTL_SECONDS`, and refreshed once on an unknown ``kid`` (key
    rotation).
    """

    def __init__(self, base_url: str, http_client: httpx.Client) -> None:
        self._jwks_url = base_url.rstrip("/") + "/.well-known/jwks.json"
        self._http = http_client
        self._keys: Optional[Dict[str, ec.EllipticCurvePublicKey]] = None
        self._fetched_at = 0.0

    def verify(
        self, token: str, options: Optional[VerifyOptions] = None
    ) -> SessionClaims:
        """Verify ``token``'s ES256 signature against the JWKS, then validate
        expiry / not-before / issuer / audience. Returns :class:`SessionClaims`
        or raises :class:`SessionVerificationError`.
        """
        opts = options or VerifyOptions()
        skew = opts.clock_tolerance_seconds if opts.clock_tolerance_seconds else 30

        parts = token.split(".")
        if len(parts) != 3:
            raise SessionVerificationError("malformed token")
        h, p, s = parts

        header = _decode_segment(h)
        if header.get("alg") != "ES256":
            raise SessionVerificationError(f"unsupported alg {header.get('alg')}")
        kid = header.get("kid") if isinstance(header.get("kid"), str) else None

        key = self._resolve_key(kid)

        sig = _b64url_decode(s)
        if len(sig) != 64:
            raise SessionVerificationError("malformed signature")
        # JWS ES256 carries the raw IEEE-P1363 r||s signature; convert it to the
        # DER form the cryptography library verifies, exactly like the Go SDK
        # splits sig[:32]/sig[32:] into big.Ints.
        r = int.from_bytes(sig[:32], "big")
        ss = int.from_bytes(sig[32:], "big")
        der = utils.encode_dss_signature(r, ss)
        try:
            key.verify(der, f"{h}.{p}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise SessionVerificationError("signature verification failed") from exc

        payload = _decode_segment(p)
        now = int(time.time())

        exp = _int_claim(payload.get("exp"))
        if exp is None or now > exp + skew:
            raise SessionVerificationError("token expired")
        nbf = _int_claim(payload.get("nbf"))
        if nbf is not None and now + skew < nbf:
            raise SessionVerificationError("token not yet valid")
        if opts.issuer and payload.get("iss") != opts.issuer:
            raise SessionVerificationError("issuer mismatch")
        if opts.audience and not _audience_matches(payload.get("aud"), opts.audience):
            raise SessionVerificationError("audience mismatch")

        user_id = _str_claim(payload.get("user_id")) or _str_claim(payload.get("sub")) or ""
        return SessionClaims(
            user_id=user_id,
            tenant_id=_str_claim(payload.get("tenant_id")),
            session_id=_str_claim(payload.get("sid")),
            scope=_str_claim(payload.get("scope")),
            subject=_str_claim(payload.get("sub")) or "",
            issuer=_str_claim(payload.get("iss")),
            audience=payload.get("aud"),
            expires_at=exp,
            issued_at=_int_claim(payload.get("iat")),
            raw=payload,
        )

    # ---- key resolution / JWKS ---------------------------------------------
    def _resolve_key(self, kid: Optional[str]) -> ec.EllipticCurvePublicKey:
        key = self._lookup(kid, force_fresh=False)
        if key is None:
            self._refresh()
            key = self._lookup(kid, force_fresh=True)
        if key is None:
            raise SessionVerificationError(
                f"no JWKS key for kid {kid}" if kid else "no usable JWKS key"
            )
        return key

    def _lookup(
        self, kid: Optional[str], force_fresh: bool
    ) -> Optional[ec.EllipticCurvePublicKey]:
        if self._keys is None or (
            not force_fresh and time.time() - self._fetched_at > JWKS_TTL_SECONDS
        ):
            return None
        if not kid:
            return next(iter(self._keys.values()), None)
        return self._keys.get(kid)

    def _refresh(self) -> None:
        try:
            res = self._http.get(self._jwks_url, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise SessionVerificationError(f"JWKS fetch failed: {exc}") from exc
        if res.status_code != 200:
            raise SessionVerificationError(f"JWKS fetch failed: {res.status_code}")
        try:
            doc = res.json()
        except ValueError as exc:
            raise SessionVerificationError(f"JWKS decode failed: {exc}") from exc

        keys: Dict[str, ec.EllipticCurvePublicKey] = {}
        for jwk in doc.get("keys", []) or []:
            pub = _jwk_to_ec(jwk)
            if pub is not None:
                keys[jwk.get("kid", "")] = pub
        self._keys = keys
        self._fetched_at = time.time()


def _jwk_to_ec(jwk: Dict[str, Any]) -> Optional[ec.EllipticCurvePublicKey]:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        return None
    try:
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    except (KeyError, ValueError):
        return None
    try:
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError:
        return None


def _decode_segment(seg: str) -> Dict[str, Any]:
    try:
        out = json.loads(_b64url_decode(seg))
    except ValueError as exc:
        raise SessionVerificationError("malformed token segment") from exc
    if not isinstance(out, dict):
        raise SessionVerificationError("malformed token segment")
    return out


def _b64url_decode(seg: str) -> bytes:
    padding = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + padding)


def _str_claim(v: Any) -> Optional[str]:
    return v if isinstance(v, str) else None


def _int_claim(v: Any) -> Optional[int]:
    # JSON numbers decode to int/float; bool is a subclass of int, exclude it.
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(v)
    return None


def _audience_matches(aud: Any, want: str) -> bool:
    if isinstance(aud, str):
        return aud == want
    if isinstance(aud, list):
        return want in aud
    return False
