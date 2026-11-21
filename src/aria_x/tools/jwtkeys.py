"""JWT signing for the algorithms the decoder alone cannot produce.

`jwt_inspect` decodes, flags and can forge HMAC. That covers "weak secret", not
"RS256 without the private key" and not the two attacks that matter on real
deployments:

* **algorithm confusion** — re-sign with HS256 using the server's *public* key
  text as the HMAC secret, then flip the header to ``HS256``. A verifier that
  picks the algorithm out of the token and hands it the public key will accept
  the forgery;
* **claim tampering with a known key** — the key leaked in a `.env`, an old build
  or a git object, so any claim can be re-signed for real.

Pure stdlib on purpose (no `cryptography`): RSA PKCS#1 v1.5 EMSA by hand with
modular exponentiation, and ECDSA P-256 by hand. Keys are PEM: PKCS#1/PKCS#8 for
RSA, SEC1/PKCS#8 for EC. EC signatures are emitted as the raw JOSE ``r||s``
(not DER) — the one detail everyone gets wrong first.
"""

from __future__ import annotations

import base64
import hashlib
import json
import hmac
import secrets
from typing import Any

from ..util import json_dumps

#: alg → (hash constructor, DigestInfo prefix) for EMSA-PKCS1-v1_5.
_RSA_ALGS = {
    "RS256": (hashlib.sha256, bytes.fromhex("3031300d060960864801650304020105000420")),
    "RS384": (hashlib.sha384, bytes.fromhex("3041300d060960864801650304020205000430")),
    "RS512": (hashlib.sha512, bytes.fromhex("3051300d060960864801650304020305000440")),
}
_HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

#: P-256 domain parameters (FIPS 186-4 / SEC 2).
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
           0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------------------------------------------------------------------------
# PEM / DER
# ---------------------------------------------------------------------------


def _der_items(data: bytes) -> list[tuple[int, bytes]]:
    """Split a DER SEQUENCE body into (tag, value) pairs. Enough for key ASN.1."""
    items: list[tuple[int, bytes]] = []
    index = 0
    while index < len(data):
        tag = data[index]
        index += 1
        if index >= len(data):
            break
        length = data[index]
        index += 1
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(data[index:index + count], "big")
            index += count
        items.append((tag, data[index:index + length]))
        index += length
    return items


def _pem_body(pem: str) -> bytes:
    lines = [line.strip() for line in pem.strip().splitlines() if line.strip()]
    body = "".join(line for line in lines if not line.startswith("-----"))
    try:
        return base64.b64decode(body)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"unreadable PEM body: {exc}") from exc


def _seq(der: bytes) -> list[tuple[int, bytes]]:
    """Items of the outer SEQUENCE (PEM key bodies are always one SEQUENCE)."""
    outer = _der_items(der)
    if not outer:
        return []
    tag, body = outer[0]
    return _der_items(body) if tag == 0x30 else outer


def _der_int(value: bytes) -> int:
    return int.from_bytes(value, "big")


def rsa_private_key(pem: str) -> tuple[int, int]:
    """Extract (n, d) from a PKCS#1 or PKCS#8 RSA private key PEM."""
    n, _e, d = _rsa_triple(pem)
    return n, d


def _rsa_triple(pem: str) -> tuple[int, int, int]:
    """(n, e, d) from a private key — lets verification work without the .pub."""
    der = _pem_body(pem)
    items = _seq(der)
    if not items:
        raise ValueError("empty key")
    if b"PRIVATE KEY" in pem.encode() and b"RSA PRIVATE KEY" not in pem.encode():
        # PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING(pkcs1) }
        inner = next((value for tag, value in items if tag == 0x04), b"")
        items = _seq(inner)
    numbers = [_der_int(value) for tag, value in items if tag == 0x02]
    if len(numbers) < 5:
        raise ValueError("not an RSA private key")
    # PKCS#1: version, n, e, d, p, q, ...
    return numbers[1], numbers[2], numbers[3]


def ec_private_key(pem: str) -> tuple[int, int]:
    """Return the P-256 private scalar from a SEC1 or PKCS#8 EC key PEM."""
    der = _pem_body(pem)
    items = _seq(der)
    if not items:
        raise ValueError("empty key")
    if b"BEGIN EC PRIVATE KEY" not in pem.encode():
        # PKCS#8 wraps the SEC1 structure in an OCTET STRING
        inner = next((value for tag, value in items if tag == 0x04), b"")
        items = _seq(inner)
    scalar = next((value for tag, value in items if tag == 0x04), b"")
    if not scalar:
        raise ValueError("not an EC private key")
    return int.from_bytes(scalar, "big"), 0


# ---------------------------------------------------------------------------
# RSA PKCS#1 v1.5
# ---------------------------------------------------------------------------


def _rsa_sign(alg: str, message: bytes, n: int, d: int) -> bytes:
    digest_fn, info = _RSA_ALGS[alg]
    digest = digest_fn(message).digest()
    size = (n.bit_length() + 7) // 8
    padding = size - len(info) - len(digest) - 3
    if padding < 8:
        raise ValueError("key too small for this digest")
    block = b"\x00\x01" + b"\xff" * padding + b"\x00" + info + digest
    signature = pow(int.from_bytes(block, "big"), d, n)
    return signature.to_bytes(size, "big")


def _rsa_verify(alg: str, message: bytes, signature: bytes, n: int, e: int) -> bool:
    digest_fn, info = _RSA_ALGS[alg]
    size = (n.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    block = pow(int.from_bytes(signature, "big"), e, n).to_bytes(size, "big")
    expected = digest_fn(message).digest()
    return block.endswith(info + expected)


def rsa_public_key(pem: str) -> tuple[int, int]:
    """Extract (n, e) from a SubjectPublicKeyInfo or PKCS#1 public key PEM."""
    der = _pem_body(pem)
    items = _seq(der)
    numbers = [_der_int(value) for tag, value in items if tag == 0x02]
    if len(numbers) >= 2:
        return numbers[0], numbers[1]          # PKCS#1 RSAPublicKey
    bits = next((value for tag, value in items if tag == 0x03), b"")
    numbers = [_der_int(value) for tag, value in _seq(bits[1:]) if tag == 0x02]
    if len(numbers) < 2:
        raise ValueError("not an RSA public key")
    return numbers[0], numbers[1]


# ---------------------------------------------------------------------------
# ECDSA P-256 (JOSE raw r||s)
# ---------------------------------------------------------------------------


def _point_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P256_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] + _P256_A) * pow(2 * p[1], -1, _P256_P) % _P256_P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P256_P) % _P256_P
    x = (lam * lam - p[0] - q[0]) % _P256_P
    return x, (lam * (p[0] - x) - p[1]) % _P256_P


def _point_mul(scalar: int, point: tuple[int, int] = _P256_G) -> tuple[int, int]:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _ec_sign(message: bytes, d: int) -> bytes:
    digest = hashlib.sha256(message).digest()
    z = int.from_bytes(digest, "big")
    while True:
        k = secrets.randbelow(_P256_N - 1) + 1
        point = _point_mul(k)
        r = point[0] % _P256_N
        if not r:
            continue
        s = (pow(k, -1, _P256_N) * (z + r * d)) % _P256_N
        if s:
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _ec_public_from_d(d: int) -> tuple[int, int]:
    return _point_mul(d)


def _ec_verify(message: bytes, signature: bytes, public: tuple[int, int]) -> bool:
    if len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (0 < r < _P256_N and 0 < s < _P256_N):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, _P256_N)
    point = _point_add(_point_mul(z * w % _P256_N), _point_mul(r * w % _P256_N, public))
    return point is not None and point[0] % _P256_N == r


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def sign(alg: str, claims: dict[str, Any], *, key_pem: str = "", header: dict[str, Any] | None = None,
         hmac_secret: str = "") -> dict[str, Any]:
    """Produce a signed token. Returns ``{token, alg, note}``.

    ``key_pem`` is a private key for RS*/ES*; for ``hs-confusion`` the *public*
    key text becomes the HMAC secret, which is the whole point of that trick.
    """
    alg = alg.upper()
    jose_header: dict[str, Any] = {"typ": "JWT", "alg": alg}
    if header:
        jose_header.update(header)
    signing_input = f"{_b64(json_dumps(jose_header).encode())}.{_b64(json_dumps(claims).encode())}"
    message = signing_input.encode()

    if alg == "NONE":
        return {"token": signing_input + ".", "alg": "none",
                "note": "unsigned — the verifier must accept alg=none"}
    if alg in _HMAC_ALGS:
        secret = (hmac_secret or key_pem).encode()
        if not secret:
            raise ValueError("HS* needs a secret (or the public key text for confusion)")
        digest = hmac.new(secret, message, _HMAC_ALGS[alg]).digest()
        note = "HMAC with public key as secret (algorithm confusion)" if key_pem and not hmac_secret \
            else "HMAC"
        return {"token": f"{signing_input}.{_b64(digest)}", "alg": alg, "note": note}
    if alg in _RSA_ALGS:
        n, d = rsa_private_key(key_pem)
        return {"token": f"{signing_input}.{_b64(_rsa_sign(alg, message, n, d))}", "alg": alg,
                "note": f"RSA {alg}"}
    if alg == "ES256":
        d, _ = ec_private_key(key_pem)
        return {"token": f"{signing_input}.{_b64(_ec_sign(message, d))}", "alg": alg,
                "note": "ECDSA P-256, raw r||s"}
    raise ValueError(f"unsupported alg '{alg}' (none, HS256/384/512, RS256/384/512, ES256)")


def verify(token: str, *, key_pem: str = "", hmac_secret: str = "") -> dict[str, Any]:
    """Check a token against a public key or an HMAC secret. Returns a verdict dict."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"valid": False, "detail": "not a 3-segment token"}
    try:
        header = json.loads(_b64d(parts[0]))
    except ValueError:
        return {"valid": False, "detail": "header is not JSON"}
    alg = str(header.get("alg") or "").upper()
    message = f"{parts[0]}.{parts[1]}".encode()
    try:
        signature = _b64d(parts[2]) if parts[2] else b""
    except ValueError:
        return {"valid": False, "detail": "signature is not base64url"}
    if alg == "NONE":
        return {"valid": not signature, "alg": "none", "detail": "alg=none accepted only if unsigned"}
    if alg in _HMAC_ALGS:
        expected = hmac.new((hmac_secret or key_pem).encode(), message, _HMAC_ALGS[alg]).digest()
        return {"valid": hmac.compare_digest(expected, signature), "alg": alg, "detail": "HMAC"}
    if alg in _RSA_ALGS:
        try:
            n, e = rsa_public_key(key_pem)
        except ValueError:
            n, e, _d = _rsa_triple(key_pem)   # private key given: e comes with it
        return {"valid": _rsa_verify(alg, message, signature, n, e), "alg": alg, "detail": "RSA"}
    if alg == "ES256":
        d, _ = ec_private_key(key_pem)
        return {"valid": _ec_verify(message, signature, _ec_public_from_d(d)), "alg": alg,
                "detail": "ECDSA"}
    return {"valid": False, "detail": f"unsupported alg '{alg}'"}
