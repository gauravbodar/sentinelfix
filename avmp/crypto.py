"""Asymmetric signing (Phase 4 D2) — pure-Python RSA.

Real RSA signatures: the private key signs on the trusted build host; the
appliance verifies with the PUBLIC KEY ONLY and fails closed on tamper. This is
genuine asymmetric crypto with no third-party dependency, so it runs on a sealed
appliance.

NOT FIPS-validated. Production swaps in a FIPS 140-2/3 validated module (e.g.
OpenSSL FIPS provider) with real X.509/PEM keys in an HSM/KMS — the bundle
format and the sign/verify flow are identical, only the crypto provider changes.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path

_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


def _miller_rabin(n: int, a: int) -> bool:
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    x = pow(a, d, n)
    if x in (1, n - 1):
        return True
    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
    return False


def _is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    for _ in range(rounds):
        if not _miller_rabin(n, secrets.randbelow(n - 3) + 2):
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand):
            return cand


@dataclass
class PublicKey:
    n: int
    e: int


@dataclass
class PrivateKey:
    n: int
    e: int
    d: int

    def public(self) -> PublicKey:
        return PublicKey(self.n, self.e)


def generate_keypair(bits: int = 2048) -> PrivateKey:
    half = bits // 2
    p = _gen_prime(half)
    q = _gen_prime(half)
    while q == p:
        q = _gen_prime(half)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return PrivateKey(n, e, d)


def _digest_int(msg: bytes, n: int) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % n


def sign(msg: bytes, priv: PrivateKey) -> str:
    return format(pow(_digest_int(msg, priv.n), priv.d, priv.n), "x")


def verify(msg: bytes, sig_hex: str, pub: PublicKey) -> bool:
    try:
        s = int(sig_hex, 16)
    except (ValueError, TypeError):
        return False
    return pow(s, pub.e, pub.n) == _digest_int(msg, pub.n)


# --- persistence (JSON; production uses PEM/PKCS behind the same API) -------
def save_private(priv: PrivateKey, path: str) -> None:
    Path(path).write_text(json.dumps({"n": priv.n, "e": priv.e, "d": priv.d}), encoding="utf-8")


def load_private(path: str) -> PrivateKey:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return PrivateKey(d["n"], d["e"], d["d"])


def save_public(pub: PublicKey, path: str) -> None:
    Path(path).write_text(json.dumps({"n": pub.n, "e": pub.e}), encoding="utf-8")


def load_public(path: str) -> PublicKey:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return PublicKey(d["n"], d["e"])
